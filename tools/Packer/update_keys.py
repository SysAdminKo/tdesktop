#!/usr/bin/env python3
"""
Manage the v2 update trust chain of TelegramWSS.

    python update_keys.py init      # once: root + release key, manifest v1
    python update_keys.py rotate    # new release key, old one revoked
    python update_keys.py show      # print the current manifest

The root key only signs the manifest and is never used for packages.
The release key signs packages and is listed in the manifest for every
channel. The client embeds root-public.pem + manifest at build time and
adopts newer manifests carried inside packages, so a rotated release key
reaches clients with the next update.

Private keys go to tools/Packer/keys/ (gitignored), public trust files to
Telegram/Resources/update/ (committed, rebuilt into the client).
"""
from __future__ import annotations

import argparse
import json
import sys
import time

import update_v2 as v2

MANIFEST_LIFETIME = 5 * 365 * 24 * 60 * 60


def write_manifest(
        root: v2.ECC.EccKey,
        version: int,
        release_id: str,
        release: v2.ECC.EccKey,
        revoked: list[str]) -> None:
    now = int(time.time())
    manifest = {
        'format': 1,
        'manifest_version': version,
        'issued': now,
        'expires': now + MANIFEST_LIFETIME,
        'keys': [{
            'id': release_id,
            'alg': 'Ed25519',
            'x': v2.b64url(v2.public_raw(release)),
        }],
        'channels': {
            name: [[release_id]] for name in v2.CHANNELS
        },
        'revoked': revoked,
    }
    data = v2.manifest_bytes(manifest)
    v2.TRUST_DIR.mkdir(parents=True, exist_ok=True)
    v2.ROOT_PUBLIC_FILE.write_bytes(v2.public_pem(root))
    v2.MANIFEST_FILE.write_bytes(data)
    v2.MANIFEST_SIG_FILE.write_bytes(v2.sign(root, data))
    v2.load_trust()
    print(f'Manifest v{version} with key {release_id} -> {v2.TRUST_DIR}')


def cmd_init(args: argparse.Namespace) -> None:
    if v2.ROOT_PRIVATE_FILE.exists() and not args.force:
        raise v2.UpdateV2Error(
            f'{v2.ROOT_PRIVATE_FILE} exists, use --force to replace '
            'the whole trust chain (clients built with the old root '
            'will stop accepting updates)')
    root = v2.generate_key()
    release_id = 'wss-rl-1'
    release = v2.generate_key()
    v2.save_private_key(root, v2.ROOT_PRIVATE_FILE)
    v2.save_private_key(release, v2.release_key_file(release_id))
    write_manifest(root, 1, release_id, release, [])
    print('Keep keys/ backed up offline: losing the root key means '
          'clients can never get a rotated release key.')


def cmd_rotate(args: argparse.Namespace) -> None:
    trust = v2.load_trust()
    root = v2.load_private_key(v2.ROOT_PRIVATE_FILE)
    if v2.public_pem(root) != trust.root_pem:
        raise v2.UpdateV2Error('keys/ root key does not match root-public.pem')
    old_id = v2.channel_key_id(trust.parsed, 'stable')
    prefix, _, number = old_id.rpartition('-')
    release_id = f'{prefix}-{int(number) + 1}'
    release = v2.generate_key()
    v2.save_private_key(release, v2.release_key_file(release_id))
    revoked = list(trust.parsed.get('revoked', []))
    if args.revoke_old:
        revoked.append(old_id)
    write_manifest(
        root,
        trust.parsed['manifest_version'] + 1,
        release_id,
        release,
        revoked)


def cmd_show(_: argparse.Namespace) -> None:
    trust = v2.load_trust()
    print(json.dumps(trust.parsed, indent=2))
    print('Root signature: OK')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init', help='create root + release keys')
    init.add_argument('--force', action='store_true')
    rotate = sub.add_parser('rotate', help='issue a new release key')
    rotate.add_argument('--keep-old', dest='revoke_old',
                        action='store_false',
                        help='do not revoke the previous release key')
    sub.add_parser('show', help='verify and print the manifest')
    args = parser.parse_args()
    try:
        {'init': cmd_init, 'rotate': cmd_rotate, 'show': cmd_show}[
            args.command](args)
    except v2.UpdateV2Error as e:
        print(f'ERROR: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
