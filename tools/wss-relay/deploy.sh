#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-/opt/wss-relay}"
REMOTE_SRC="${INSTALL_DIR}/src"
SSH_OPTS=(${SSH_OPTS:-})
RSYNC_OPTS=(${RSYNC_OPTS:--az --delete})

usage() {
	cat <<'EOF'
Usage: ./deploy.sh [options] user@host

Deploy wss-relay to a remote Linux host over SSH.
Sources are synced to /opt/wss-relay/src and built on the server.

Options:
  --check-only   Verify local/remote prerequisites, do not deploy
  --listen ADDR  Relay listen address (default: 127.0.0.1:8283)
  -h, --help     Show this help

Environment:
  INSTALL_DIR    Remote install root (default: /opt/wss-relay)
  SSH_OPTS       Extra ssh options (array)
  RSYNC_OPTS     Extra rsync options (array)

Examples:
  ./deploy.sh root@31.76.21.175
  ./deploy.sh --check-only root@31.76.21.175
  LISTEN_ADDR=127.0.0.1:8283 ./deploy.sh root@example.com
EOF
}

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

check_local_prerequisites() {
	log "Checking local prerequisites..."
	require_cmd ssh "install OpenSSH client"
	if command -v rsync >/dev/null 2>&1; then
		SYNC_MODE=rsync
	elif command -v tar >/dev/null 2>&1 && command -v scp >/dev/null 2>&1; then
		SYNC_MODE=tar
	else
		fail "need rsync or tar+scp for file sync"
	fi
	log "Local prerequisites OK (sync via ${SYNC_MODE})"
}

parse_args() {
	CHECK_ONLY=0
	LISTEN_ADDR="${LISTEN_ADDR:-127.0.0.1:8283}"
	DEPLOY_HOST=""
	while (($#)); do
		case "$1" in
		--check-only)
			CHECK_ONLY=1
			;;
		--listen)
			shift
			LISTEN_ADDR="${1:?--listen requires an address}"
			;;
		-h|--help)
			usage
			exit 0
			;;
		-*)
			fail "unknown option: $1"
			;;
		*)
			[[ -z "$DEPLOY_HOST" ]] || fail "unexpected argument: $1"
			DEPLOY_HOST="$1"
			;;
		esac
		shift
	done
	[[ -n "$DEPLOY_HOST" ]] || fail "missing user@host (see: ./deploy.sh --help)"
}

remote_exec() {
	ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" "$@"
}

sync_sources() {
	log "Syncing sources to ${DEPLOY_HOST}:${REMOTE_SRC}..."
	remote_exec "mkdir -p '${REMOTE_SRC}'"
	if [[ "${SYNC_MODE}" == rsync ]]; then
		rsync "${RSYNC_OPTS[@]}" \
			-e "ssh ${SSH_OPTS[*]}" \
			--exclude '.git/' \
			--exclude '*.exe' \
			--exclude 'deploy.sh' \
			--exclude 'deploy.ps1' \
			--exclude 'deploy.cmd' \
			"${SCRIPT_DIR}/" "${DEPLOY_HOST}:${REMOTE_SRC}/"
	else
		local archive
		archive="$(mktemp "${TMPDIR:-/tmp}/wss-relay-src.XXXXXX.tar.gz")"
		trap 'rm -f "$archive"' RETURN
		tar -C "${SCRIPT_DIR}" -czf "$archive" \
			--exclude='.git' \
			--exclude='*.exe' \
			--exclude='deploy.sh' \
			--exclude='deploy.ps1' \
			--exclude='deploy.cmd' \
			.
		scp "${SSH_OPTS[@]}" "$archive" "${DEPLOY_HOST}:/tmp/wss-relay-src.tar.gz"
		remote_exec "tar -xzf /tmp/wss-relay-src.tar.gz -C '${REMOTE_SRC}' && rm -f /tmp/wss-relay-src.tar.gz"
	fi
	log "Sources synced"
	remote_exec "find '${REMOTE_SRC}' -name '*.sh' -exec sed -i 's/\\r$//' {} +"
}

run_remote() {
	local mode="$1"
	remote_exec \
		"INSTALL_DIR='${INSTALL_DIR}' LISTEN_ADDR='${LISTEN_ADDR}' bash '${REMOTE_SRC}/remote-build.sh' '${mode}'"
}

main() {
	parse_args "$@"
	check_local_prerequisites
	log "Target: ${DEPLOY_HOST}"
	log "Install dir: ${INSTALL_DIR}"
	if (( CHECK_ONLY )); then
		sync_sources
		run_remote check
		log "Remote prerequisites OK"
		exit 0
	fi
	sync_sources
	run_remote deploy
	log "Done. Stats: ssh -L 8283:${LISTEN_ADDR} ${DEPLOY_HOST}  then open http://127.0.0.1:8283/stats"
}

main "$@"
