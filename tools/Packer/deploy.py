#!/usr/bin/env python3
"""
Deploy an update to the custom update server.

Builds the client, packs the update file, generates current4 JSON,
uploads everything to the server via SSH/SFTP.

Usage:
    python3 deploy.py --bump --platform win64 \
        --host update@cdn.honeydrinksomewine.com \
        --remote-path /home/update/www

    python3 deploy.py --version 6009301 --platform win64 \
        --host update@cdn.honeydrinksomewine.com
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

from bump_version import apply_version, bump, parse_version_input

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, '..', '..'))
PACKER_SCRIPT = os.path.join(BASE_DIR, 'packer.py')

DEFAULT_PRIVATE_KEY = os.path.join(BASE_DIR, 'keys', 'stable_private.pem')


def run(cmd, cwd=None):
    print(f"  RUN: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  STDERR: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(result.returncode)
    return result.stdout.strip()


def build_client(build_dir):
    print("=== Building client ===")
    cmake_build = os.path.join(REPO_ROOT, 'out')
    if build_dir:
        cmake_build = build_dir
    run(['cmake', '--build', cmake_build, '--config', 'Release',
         '--target', 'Telegram'], cwd=REPO_ROOT)
    return cmake_build


def collect_build_files(build_dir_abs, tmp_dir, platform):
    print("=== Collecting build files ===")

    if platform.startswith('win'):
        release_dir = os.path.join(build_dir_abs, 'Release')
        if not os.path.isdir(release_dir):
            release_dir = build_dir_abs

        if not os.path.isdir(release_dir):
            print(f"ERROR: build output not found: {release_dir}",
                  file=sys.stderr)
            sys.exit(1)

        print(f"  Copying from: {release_dir}")
        copied = 0
        for item in os.listdir(release_dir):
            if item.endswith('.pdb'):
                continue
            src = os.path.join(release_dir, item)
            if os.path.isdir(src):
                dst = os.path.join(tmp_dir, item)
                shutil.copytree(src, dst, dirs_exist_ok=True)
                copied += sum(1 for _ in os.walk(dst))
            elif os.path.isfile(src):
                shutil.copy2(src, tmp_dir)
                copied += 1
        print(f"  Copied ~{copied} items")
    else:
        if os.path.isdir(build_dir_abs):
            print(f"  Copying from: {build_dir_abs}")
            shutil.copytree(build_dir_abs, tmp_dir, dirs_exist_ok=True,
                            symlinks=True)
        else:
            print(f"ERROR: build dir not found: {build_dir_abs}",
                  file=sys.stderr)
            sys.exit(1)

    return tmp_dir


def pack_update(tmp_dir, version, platform, private_key, alpha):
    print("=== Packing update ===")
    cmd = [
        sys.executable, PACKER_SCRIPT,
        '--path', tmp_dir,
        '--version', str(version),
        '--platform', platform,
        '--private-key', private_key,
    ]
    if alpha:
        cmd += ['--alpha', str(alpha)]
    output = run(cmd, cwd=BASE_DIR)
    print(output)

    for line in output.split('\n'):
        if 'written successfully' in line:
            fname = line.split("'")[1]
            return fname

    print("ERROR: could not determine output filename from packer",
          file=sys.stderr)
    sys.exit(1)


def generate_current4(version, platform, base_url, filename):
    print("=== Generating current4 ===")
    doc = {
        platform: {
            "stable": {
                "released": version,
                "link": f"/files/{filename}",
            }
        }
    }
    return json.dumps(doc, indent=2) + '\n'


def upload(host, remote_path, local_file, current4_content, ssh_key):
    import paramiko

    print(f"=== Uploading to {host}:{remote_path} ===")

    user_host = host.split('@')
    username = user_host[0] if len(user_host) == 2 else None
    hostname = user_host[1] if len(user_host) == 2 else host

    def load_key(path):
        path = os.path.expanduser(path)
        for cls in [paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey]:
            try:
                return cls.from_private_key_file(path)
            except Exception:
                continue
        return None

    key = None
    if ssh_key:
        key = load_key(ssh_key)
    if not key:
        for p in ['~/.ssh/id_ed25519', '~/.ssh/id_rsa']:
            key = load_key(p)
            if key:
                break

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname, username=username, pkey=key)

    sftp = client.open_sftp()

    remote_files_dir = f"{remote_path}/files"
    try:
        sftp.stat(remote_files_dir)
    except FileNotFoundError:
        sftp.mkdir(remote_files_dir)

    remote_file = f"{remote_files_dir}/{os.path.basename(local_file)}"
    sftp.put(local_file, remote_file)
    print(f"  {os.path.basename(local_file)} -> {remote_file}")

    existing = {}
    try:
        with sftp.open(f"{remote_path}/current4", 'r') as f:
            existing = json.loads(f.read().decode('utf-8'))
        print("  Merging with existing current4...")
    except (FileNotFoundError, json.JSONDecodeError):
        print("  Creating new current4...")

    new_doc = json.loads(current4_content)
    existing.update(new_doc)
    merged = json.dumps(existing, indent=2) + '\n'

    with sftp.open(f"{remote_path}/current4", 'w') as f:
        f.write(merged)
    print(f"  current4 -> {remote_path}/current4 ({len(merged)} bytes)")

    sftp.close()
    client.close()


def main():
    parser = argparse.ArgumentParser(
        description='Deploy update to custom update server')
    parser.add_argument('--version', default=None,
                        help='Pack version: 6009301 or 6.9.301 (overrides --bump)')
    parser.add_argument('--bump', action='store_true',
                        help='Bump patch in source files via bump_version.py')
    parser.add_argument('--set-version', metavar='VERSION',
                        help='Set version in source files without bumping')
    parser.add_argument('--platform', default='win64',
                        choices=['win', 'win64', 'winarm', 'mac', 'armac', 'linux'])
    parser.add_argument('--host', required=True)
    parser.add_argument('--remote-path', default='/home/update/www')
    parser.add_argument('--build-dir')
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--private-key', default=DEFAULT_PRIVATE_KEY)
    parser.add_argument('--ssh-key')
    parser.add_argument('--base-url', default='https://cdn.honeydrinksomewine.com')
    parser.add_argument('--pack-dir',
                        help='Use existing directory with files (skip build+collect)')
    parser.add_argument('--alpha', type=int, default=0)
    args = parser.parse_args()

    if args.set_version:
        version, _ = parse_version_input(args.set_version)
        apply_version(version)
        if args.version is None:
            args.version = version

    if args.bump:
        bumped, _ = bump()
        if args.version is None:
            args.version = bumped
        else:
            pack_version, _ = parse_version_input(str(args.version))
            if pack_version != bumped:
                print(f"  --version overrides bump: {pack_version} (bumped was {bumped})")
            args.version = pack_version
    elif args.version is not None:
        args.version, _ = parse_version_input(str(args.version))
    elif args.set_version is None:
        print("ERROR: specify --version, --bump, or --set-version", file=sys.stderr)
        sys.exit(1)

    if args.pack_dir:
        tmp_dir = args.pack_dir
        cleanup_tmp = False
        print(f"Using existing pack dir: {tmp_dir}")
    else:
        if not args.no_build:
            build_dir = build_client(args.build_dir)
        else:
            build_dir = args.build_dir or os.path.join(REPO_ROOT, 'out', 'Release')

        tmp_dir_obj = tempfile.TemporaryDirectory(prefix='pack_deploy_')
        tmp_dir = tmp_dir_obj.name
        cleanup_tmp = True
        collect_build_files(build_dir, tmp_dir, args.platform)

    try:
        filename = pack_update(
            tmp_dir, args.version, args.platform,
            args.private_key, args.alpha)

        local_file = filename if os.path.isabs(filename) \
            else os.path.join(BASE_DIR, filename)
        if not os.path.isfile(local_file):
            print(f"ERROR: packed file not found: {local_file}", file=sys.stderr)
            sys.exit(1)

        current4_content = generate_current4(
            args.version, args.platform, args.base_url,
            os.path.basename(local_file))

        upload(args.host, args.remote_path, local_file,
               current4_content, args.ssh_key)

        print(f"\n=== Deploy complete ===")
        print(f"  Version: {args.version}")
        print(f"  Platform: {args.platform}")
        print(f"  URL: {args.base_url}/files/{filename}")
        print(f"  Check: curl {args.base_url}/current4")
    finally:
        if cleanup_tmp:
            try:
                tmp_dir_obj.cleanup()
            except Exception:
                pass


if __name__ == '__main__':
    main()
