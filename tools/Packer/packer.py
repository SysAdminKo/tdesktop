#!/usr/bin/env python3
"""
Packer for Telegram Desktop update files.
Reproduces the binary format of QDataStream Qt 5.1 + LZMA, signed as
v1 (RSA-SHA1, clients up to 7.2.x) and/or v2 (Ed25519 TDUP envelope,
clients 7.3+, see update_v2.py). One compression feeds both formats.

Usage:
    python3 packer.py --path <build_dir> \
        --platform <win64|win|winarm|mac|armac|linux> \
        [--format v1|v2|both] [--private-key <rsa.pem>] \
        [--version <version>] [--current4]

Minimal example (version from core/version.h, output in Release/ for v1
and Release/v2/ for v2):

    cd tools/Packer
    python packer.py --path ..\\..\\out\\Release --platform win64 ^
        --private-key keys\\stable_private.pem --current4

Binary structure of the v1 output file:

    Windows:
        [128b RSA-1024 signature]
        [20b  SHA-1 hash]
        [5b   LZMA properties]
        [4b   uncompressed size (int32 LE)]
        [...  LZMA compressed data ...]

    Linux/macOS:
        [128b RSA-1024 signature]
        [20b  SHA-1 hash]
        [4b   uncompressed size (int32 LE)]
        [...  LZMA/xz compressed data ...]

Inner QDataStream format (before compression) — Qt 5.1, big-endian:
    uint32  version (or 0x7FFFFFFF for alpha + uint64 alphaVersion)
    uint32  filesCount
    For each file:
        QString  relativeName  (uint32 byteCount + UTF-16BE)
        uint32   fileSize
        QByteArray fileData   (uint32 byteCount + raw bytes)
        bool     executable    (non-Windows only, 1 byte)
"""
import argparse
import json
import lzma
import os
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import update_v2 as v2
from bump_version import parse_version_input, read_current_version


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, 'Release')

H_SIG_LEN = 128
H_SHA_LEN = 20
H_PROPS_LEN_WIN = 5    # LZMA_PROPS_SIZE

ALPHA_VERSION_MARKER = 0x7FFFFFFF


def collect_files(root_dir):
    files = []
    root_abs = os.path.abspath(root_dir)
    for dirpath, dirnames, filenames in os.walk(root_abs):
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        for fn in filenames:
            if fn.startswith('.') or fn.endswith('.pdb'):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root_abs).replace('\\', '/')
            files.append((rel, full))
    files.sort(key=lambda x: x[0])
    return files


def write_qstring(buf, s):
    utf16 = s.encode('utf-16-be')
    buf += struct.pack('>I', len(utf16))
    buf += utf16


def write_qbytearray(buf, data):
    buf += struct.pack('>I', len(data))
    buf += data


def write_quint32(buf, val):
    buf += struct.pack('>I', val)


def write_quint64(buf, val):
    buf += struct.pack('>Q', val)


def _read_file_entry(item):
    rel_name, full_path = item
    with open(full_path, 'rb') as f:
        raw = f.read()
    executable = os.access(full_path, os.X_OK) if sys.platform != 'win32' else False
    return rel_name, raw, executable


def build_datastream(version, files, workers=1):
    if workers > 1 and len(files) > 1:
        with ThreadPoolExecutor(max_workers=min(workers, len(files))) as pool:
            entries = list(pool.map(_read_file_entry, files))
    else:
        entries = [_read_file_entry(item) for item in files]

    buf = bytearray()

    write_quint32(buf, version)

    write_quint32(buf, len(files))

    for rel_name, raw, executable in entries:
        write_qstring(buf, rel_name)
        write_quint32(buf, len(raw))
        write_qbytearray(buf, raw)

        if sys.platform != 'win32':
            buf.append(0x01 if executable else 0x00)

    return buf


def compress_xz(uncompressed, threads):
    preset = 9 | lzma.PRESET_EXTREME
    if threads == 1:
        return lzma.compress(
            uncompressed,
            format=lzma.FORMAT_XZ,
            preset=preset,
            check=lzma.CHECK_CRC64,
        )

    filter_opts = {
        'id': lzma.FILTER_LZMA2,
        'preset': preset,
        'threads': threads or (os.cpu_count() or 1),
    }
    try:
        return lzma.compress(
            uncompressed,
            format=lzma.FORMAT_XZ,
            filters=[filter_opts],
            check=lzma.CHECK_CRC64,
        )
    except ValueError:
        print("Note: multithreaded XZ not supported by this liblzma build")
        return lzma.compress(
            uncompressed,
            format=lzma.FORMAT_XZ,
            preset=preset,
            check=lzma.CHECK_CRC64,
        )


def compress_payload(uncompressed, is_windows, threads=0):
    """[lzma props on Windows,] int32 original size, compressed bytes.

    This is the v1 file without RSA signature and SHA-1 and, verbatim,
    the v2 envelope payload.
    """
    if is_windows:
        if threads > 1:
            print("Note: win64 LZMA1 compression is single-threaded (format limit)")
        filters = [{
            'id': lzma.FILTER_LZMA1,
            'preset': 9,
            'dict_size': 64 * 1024 * 1024,
            'lc': 4,
            'lp': 0,
            'pb': 2,
        }]
        compressed_with_header = lzma.compress(
            uncompressed,
            format=lzma.FORMAT_ALONE,
            filters=filters,
        )
        lzma_props = compressed_with_header[:H_PROPS_LEN_WIN]
        compressed_data = compressed_with_header[13:]
    else:
        lzma_props = b''
        compressed_data = compress_xz(uncompressed, threads)

    print(f"Original: {len(uncompressed)} bytes")
    print(f"Compressed: {len(compressed_data)} bytes")

    return (lzma_props
            + struct.pack('<i', len(uncompressed))
            + compressed_data)


def sign_v1(payload, private_key_pem):
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Signature import pkcs1_15
        from Crypto.Hash import SHA1
    except ImportError:
        print("ERROR: pycryptodome is required. Install with: pip install pycryptodome",
              file=sys.stderr)
        sys.exit(1)

    result = bytearray(H_SIG_LEN + H_SHA_LEN) + payload

    data_for_hash = bytes(payload)
    h = SHA1.new(data_for_hash)
    sha1_digest = h.digest()
    result[H_SIG_LEN:H_SIG_LEN + H_SHA_LEN] = sha1_digest

    print("Signing...")
    key = RSA.import_key(private_key_pem)
    if key.size_in_bytes() != H_SIG_LEN:
        print(f"ERROR: Bad private key size: {key.size_in_bytes()}, expected {H_SIG_LEN}",
              file=sys.stderr)
        sys.exit(1)

    signature = pkcs1_15.new(key).sign(h)
    if len(signature) != H_SIG_LEN:
        print(f"ERROR: Bad signature length: {len(signature)}", file=sys.stderr)
        sys.exit(1)
    result[:H_SIG_LEN] = signature

    print("Verifying signature...")
    try:
        pub_key = key.publickey()
        h_verify = SHA1.new(data_for_hash)
        pkcs1_15.new(pub_key).verify(h_verify, signature)
        print("Signature verified OK")
    except (ValueError, TypeError) as e:
        print(f"ERROR: Signature verification failed: {e}", file=sys.stderr)
        sys.exit(1)

    return bytes(result)


def output_name(version, platform, alpha_version):
    prefixes = {
        'win': 'tupdate',
        'win64': 'tx64upd',
        'winarm': 'tarm64upd',
        'mac': 'tmacupd',
        'armac': 'tarmacupd',
        'linux': 'tlinuxupd',
    }
    prefix = prefixes.get(platform, 'tupdate')
    ver = alpha_version if alpha_version else version
    name = f"{prefix}{ver}"
    return name


def write_current4(out_dir, platform, channel, version, out_base):
    doc = {
        platform: {
            channel: {
                "released": version,
                "link": f"/files/{out_base}",
            }
        }
    }
    current4_path = os.path.join(out_dir, 'current4')
    with open(current4_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(json.dumps(doc, indent=2) + '\n')
    print(f"current4 -> '{current4_path}'")


def write_v1(args, payload):
    with open(args.private_key, 'rb') as f:
        private_key_pem = f.read()
    result = sign_v1(payload, private_key_pem)

    out_name = args.output or output_name(args.version, args.platform, args.alpha)
    out_dir = os.path.dirname(out_name) or OUTPUT_DIR
    out_base = os.path.basename(out_name)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, out_base)
    with open(out_path, 'wb') as f:
        f.write(result)

    print(f"Update file '{out_path}' written successfully ({len(result)} bytes)")

    if args.current4:
        write_current4(out_dir, args.platform, 'stable', args.version, out_base)


def write_v2(args, payload, trust, key, key_id):
    print(f"Signing v2 with '{key_id}'...")
    result = v2.build_envelope(
        trust,
        key,
        key_id,
        args.channel,
        args.platform,
        v2.make_version(args.version),
        int(time.time()),
        payload)
    v2.verify_package(result, trust, args.channel, args.platform)
    print("v2 package verified OK")

    out_dir = os.path.join(OUTPUT_DIR, 'v2')
    out_base = v2.file_name(args.platform, args.channel, args.version)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, out_base)
    with open(out_path, 'wb') as f:
        f.write(result)

    print(f"Update file '{out_path}' written successfully ({len(result)} bytes)")

    if args.current4:
        write_current4(out_dir, args.platform, args.channel, args.version, out_base)


def main():
    parser = argparse.ArgumentParser(
        description='Pack Telegram Desktop update files')
    parser.add_argument('--path', required=True,
                        help='Directory containing files to pack')
    parser.add_argument('--version', default=None,
                        help='Version 6009301 or 6.9.301 '
                             '(default: read from core/version.h)')
    parser.add_argument('--platform', default='win64',
                        choices=list(v2.PLATFORM_TARGETS),
                        help='Target platform')
    parser.add_argument('--format', default='both', choices=['v1', 'v2', 'both'],
                        help='v1: RSA for clients up to 7.2.x, '
                             'v2: Ed25519 envelope for 7.3+ (default: both)')
    parser.add_argument('--private-key',
                        help='Path to RSA private key PEM file (v1)')
    parser.add_argument('--channel', default='stable', choices=['stable', 'beta'],
                        help='v2 channel (default: stable)')
    parser.add_argument('--output',
                        help='v1 output filename (auto-generated if not specified)')
    parser.add_argument('--alpha', type=int, default=0,
                        help='Alpha version number (0 = not alpha, v1 only)')
    parser.add_argument('--current4', action='store_true',
                        help='Generate current4 JSON alongside the update file')
    parser.add_argument('--threads', type=int, default=0,
                        help='Worker threads for file I/O and XZ compression (0 = auto)')
    args = parser.parse_args()

    make_v1 = args.format in ('v1', 'both')
    make_v2 = args.format in ('v2', 'both')

    if args.version is None:
        args.version, ver_str = read_current_version()
        print(f"Using version from code: {args.version} (\"{ver_str}\")")
    else:
        args.version, _ = parse_version_input(str(args.version))

    workers = args.threads or (os.cpu_count() or 1)

    if not os.path.isdir(args.path):
        print(f"ERROR: path does not exist: {args.path}", file=sys.stderr)
        sys.exit(1)

    if make_v1 and (not args.private_key or not os.path.isfile(args.private_key)):
        print(f"ERROR: RSA private key not found: {args.private_key}", file=sys.stderr)
        sys.exit(1)

    if make_v2:
        if args.alpha:
            print("ERROR: --alpha is supported by v1 only", file=sys.stderr)
            sys.exit(1)
        try:
            trust = v2.load_trust()
            key_id = v2.channel_key_id(trust.parsed, args.channel)
            key = v2.load_private_key(v2.release_key_file(key_id))
        except v2.UpdateV2Error as e:
            print(f"ERROR: {e} (see update_keys.py)", file=sys.stderr)
            sys.exit(1)

    is_windows = args.platform.startswith('win')

    files = collect_files(args.path)
    if not files:
        print("ERROR: no files found in path", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(files)} files:")
    for rel, full in files:
        print(f"  {rel} ({os.path.getsize(full)} bytes)")

    if args.alpha:
        version_field = ALPHA_VERSION_MARKER
    else:
        version_field = args.version

    inner = build_datastream(version_field, files, workers=workers)

    payload = compress_payload(
        bytes(inner),
        is_windows=is_windows,
        threads=args.threads,
    )

    if make_v1:
        write_v1(args, payload)
    if make_v2:
        try:
            write_v2(args, payload, trust, key, key_id)
        except v2.UpdateV2Error as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == '__main__':
    main()

