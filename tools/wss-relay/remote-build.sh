#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

INSTALL_DIR="${INSTALL_DIR:-/opt/wss-relay}"
SRC_DIR="${INSTALL_DIR}/src"
BIN_PATH="${INSTALL_DIR}/bin/wss-relay"
CONFIG_DIR="${INSTALL_DIR}/config"
TOKENS_FILE="${CONFIG_DIR}/tokens"
SERVICE_NAME="${SERVICE_NAME:-wss-relay}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
LISTEN_ADDR="${LISTEN_ADDR:-127.0.0.1:8283}"
MAX_TUNNELS_PER_IP="${MAX_TUNNELS_PER_IP:-}"
LEGACY_TOKENS="/etc/wss-relay/tokens"
MIN_GO_MAJOR=1
MIN_GO_MINOR=22

log() {
	printf '%s\n' "$*"
}

fail() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

require_cmd() {
	local name="$1"
	local hint="${2:-}"
	if ! command -v "$name" >/dev/null 2>&1; then
		[[ -n "$hint" ]] && fail "missing command: $name ($hint)"
		fail "missing command: $name"
	fi
}

check_go_version() {
	local version_line go_major go_minor go_patch rest
	version_line="$(go env GOVERSION 2>/dev/null || go version | awk '{print $3}')"
	version_line="${version_line#go}"
	IFS=. read -r go_major go_minor go_patch rest <<< "$version_line"
	[[ -n "$go_major" && -n "$go_minor" ]] || fail "cannot parse Go version: $version_line"
	if (( go_major < MIN_GO_MAJOR )) \
		|| (( go_major == MIN_GO_MAJOR && go_minor < MIN_GO_MINOR )); then
		fail "Go ${MIN_GO_MAJOR}.${MIN_GO_MINOR}+ required, found go${go_major}.${go_minor}.${go_patch:-0}"
	fi
	log "Go version: go${go_major}.${go_minor}.${go_patch:-0}"
}

check_prerequisites() {
	log "Checking prerequisites on $(hostname -f 2>/dev/null || hostname)..."
	require_cmd go "install Go ${MIN_GO_MAJOR}.${MIN_GO_MINOR}+ from https://go.dev/dl/"
	require_cmd systemctl "install systemd"
	require_cmd curl "install curl"
	require_cmd id "install coreutils"
	id nobody >/dev/null 2>&1 || fail "system user 'nobody' not found"
	check_go_version
	log "Prerequisites OK"
}

ensure_layout() {
	mkdir -p "${INSTALL_DIR}/bin" "${CONFIG_DIR}" "${SRC_DIR}"
	if [[ ! -f "${TOKENS_FILE}" && -f "${LEGACY_TOKENS}" ]]; then
		cp -a "${LEGACY_TOKENS}" "${TOKENS_FILE}"
		log "Migrated tokens from ${LEGACY_TOKENS}"
	fi
	if [[ ! -f "${TOKENS_FILE}" ]]; then
		if [[ -f "${SRC_DIR}/auth.tokens.example" ]]; then
			cp "${SRC_DIR}/auth.tokens.example" "${TOKENS_FILE}"
			chmod 640 "${TOKENS_FILE}"
			chown root:nobody "${TOKENS_FILE}" 2>/dev/null \
				|| chown root:root "${TOKENS_FILE}"
			log "Created ${TOKENS_FILE} from example — add token hashes before production use"
		fi
	fi
	if [[ -f "${TOKENS_FILE}" ]]; then
		chmod 640 "${TOKENS_FILE}"
		chown root:nobody "${TOKENS_FILE}" 2>/dev/null \
			|| chown root:root "${TOKENS_FILE}"
	fi
}

build_binary() {
	[[ -f "${SRC_DIR}/go.mod" ]] || fail "source tree not found in ${SRC_DIR}"
	log "Building ${BIN_PATH}..."
	(
		cd "${SRC_DIR}"
		GOFLAGS='-buildvcs=false' go build -ldflags='-s -w' -o "${BIN_PATH}" .
	)
	chmod 755 "${BIN_PATH}"
	log "Build OK: $(file -b "${BIN_PATH}" 2>/dev/null || ls -la "${BIN_PATH}")"
}

install_service() {
	[[ -f "${SRC_DIR}/wss-relay.service.example" ]] \
		|| fail "missing ${SRC_DIR}/wss-relay.service.example"
	if [[ -z "${MAX_TUNNELS_PER_IP}" && -f "${SERVICE_FILE}" ]]; then
		MAX_TUNNELS_PER_IP="$(sed -n 's/.*-max-tunnels-per-ip \([0-9][0-9]*\).*/\1/p' "${SERVICE_FILE}" | head -1)"
	fi
	MAX_TUNNELS_PER_IP="${MAX_TUNNELS_PER_IP:-12}"
	local auth_part=""
	if [[ -f "${TOKENS_FILE}" ]] \
		&& grep -qvE '^\s*(#|$)' "${TOKENS_FILE}" 2>/dev/null; then
		auth_part=$' \\\n\t-auth-file '"${TOKENS_FILE}"
	fi
	cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=WSS mux relay for Telegram Desktop
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nobody
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BIN_PATH} \\
	-listen ${LISTEN_ADDR} \\
	-mux-path /ws/mux \\
	-max-streams 64 \\
	-max-tunnels-per-ip ${MAX_TUNNELS_PER_IP} \\
	-stream-idle-timeout 10m \\
	-ws-ping-interval 30s \\
	-ws-read-timeout 90s \\
	-telegram-only=true${auth_part}
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/tmp

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
	systemctl enable "${SERVICE_NAME}" >/dev/null
	log "Installed ${SERVICE_FILE}"
}

restart_service() {
	log "Restarting ${SERVICE_NAME}..."
	systemctl restart "${SERVICE_NAME}"
	sleep 2
	systemctl is-active --quiet "${SERVICE_NAME}" \
		|| fail "${SERVICE_NAME} is not active (see: journalctl -u ${SERVICE_NAME} -n 50)"
}

verify_deploy() {
	local stats_url="http://${LISTEN_ADDR}/stats/json"
	log "Verifying ${stats_url}..."
	local body
	body="$(curl -fsS --max-time 5 "${stats_url}")" \
		|| fail "stats endpoint unreachable at ${stats_url}"
	case "$body" in
		*'"config"'*|*'"mux_tunnels"'*) ;;
		*) fail "unexpected stats response: ${body:0:200}" ;;
	esac
	log "Stats OK"
}

main() {
	local mode="${1:-deploy}"
	case "$mode" in
	check)
		check_prerequisites
		;;
	deploy)
		check_prerequisites
		ensure_layout
		build_binary
		install_service
		restart_service
		verify_deploy
		log "Deploy finished: ${BIN_PATH}"
		;;
	*)
		fail "usage: $0 [check|deploy]"
		;;
	esac
}

main "$@"
