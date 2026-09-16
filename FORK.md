# Fork notes (SysAdminKo/tdesktop)

## Branches

| Branch | Role |
| --- | --- |
| `dev` | Mirror of `upstream/dev` (`telegramdesktop/tdesktop`). Sync with `git fetch upstream && git reset --hard upstream/dev && git push --force-with-lease origin dev`, then `git submodule update --init --recursive` and `git fetch upstream --tags && git push origin --tags`. |
| `stable` | Product line: TCP resilience, TelegramWSS branding/CDN/updates, Packer, fork CI. |

Default product work happens on `stable`.

## Archived history (tags)

| Tag | Former branch |
| --- | --- |
| `archive/wss-mux-final` | `wss-mux` |
| `archive/fix-tcp-final` | `fix-tcp` |
| `archive/wss-mux-v2` | `wss-mux-v2` |
| `archive/ShultZ1400` | `ShultZ1400` |
| `archive/origin-dev-pre-mirror` | `origin/dev` tip before mirror reset |

Restore: `git checkout -b recovered <tag>`.

## Kept product changes (on `stable`)

- IP quarantine + `hostConnectStarted` / TLS connect stagger for slow MTProto links
- TelegramWSS `AppId` / exe name, update CDN `https://cdn.honeydrinksomewine.com`, custom RSA update keys
- `tools/Packer/` release pipeline (private keys stay local under `tools/Packer/keys/`)

## Intentionally not carried forward

- WSS mux client (`mtproto_wss_*`) and `tools/wss-relay`
- WSS proxy UI strings
- Upstream bot workflows (kept under `.github/workflows-disabled/`)

## Versioning

Fork patch channel starts at `7.2.801` (`AppVersion` `7002801`). Bump with `python tools/Packer/bump_version.py --bump` or `--set`.

## CI

Platform workflows (`linux` / `mac` / `win`) run only on `stable`.
