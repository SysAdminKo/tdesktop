#!/usr/bin/env python3
"""
Packer for Telegram Desktop update files.
Reproduces the binary format of QDataStream Qt 5.1 + LZMA + RSA-SHA1 signature.

Usage:
    python3 packer.py --path <build_dir> --version <version_int> \
        --platform <win64|win|winarm|mac|armac|linux> \
        --private-key <key.pem> [--output <filename>]

Binary structure of the output file:

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
import lzma
import os
import struct
import sys
from concurrent.futures import ThreadPoolExecutor


H_SIG_LEN = 128
H_SHA_LEN = 20
H_PROPS_LEN_WIN = 5    # LZMA_PROPS_SIZE
H_PROPS_LEN_OTHER = 0
H_ORIG_SIZE_LEN = 4

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


def compress_and_sign(uncompressed, private_key_pem, is_windows, threads=0):
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Signature import pkcs1_15
        from Crypto.Hash import SHA1
    except ImportError:
        print("ERROR: pycryptodome is required. Install with: pip install pycryptodome",
              file=sys.stderr)
        sys.exit(1)

    if is_windows:
        if threads > 1:
            print("Note: win64 LZMA1 compression is single-threaded (format limit)")
        h_props_len = H_PROPS_LEN_WIN
        h_size = H_SIG_LEN + H_SHA_LEN + h_props_len + H_ORIG_SIZE_LEN

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
        lzma_props = compressed_with_header[:5]
        compressed_data = compressed_with_header[13:]
    else:
        h_props_len = H_PROPS_LEN_OTHER
        h_size = H_SIG_LEN + H_SHA_LEN + h_props_len + H_ORIG_SIZE_LEN
        lzma_props = b''
        compressed_data = compress_xz(uncompressed, threads)

    uncompressed_size = struct.pack('<i', len(uncompressed))
    compressed_len = len(compressed_data)

    print(f"Original: {len(uncompressed)} bytes")
    print(f"Compressed: {compressed_len} bytes")

    result = bytearray(h_size + compressed_len)
    result[H_SIG_LEN + H_SHA_LEN:H_SIG_LEN + H_SHA_LEN + h_props_len] = lzma_props
    result[H_SIG_LEN + H_SHA_LEN + h_props_len:
           H_SIG_LEN + H_SHA_LEN + h_props_len + H_ORIG_SIZE_LEN] = uncompressed_size
    result[h_size:] = compressed_data

    data_for_hash = bytes(result[H_SIG_LEN + H_SHA_LEN:])
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


def main():
    parser = argparse.ArgumentParser(
        description='Pack Telegram Desktop update files')
    parser.add_argument('--path', required=True,
                        help='Directory containing files to pack')
    parser.add_argument('--version', type=int, required=True,
                        help='Numeric version (e.g. 1000005)')
    parser.add_argument('--platform', default='win64',
                        choices=['win', 'win64', 'winarm', 'mac', 'armac', 'linux'],
                        help='Target platform')
    parser.add_argument('--private-key', required=True,
                        help='Path to RSA private key PEM file')
    parser.add_argument('--output',
                        help='Output filename (auto-generated if not specified)')
    parser.add_argument('--alpha', type=int, default=0,
                        help='Alpha version number (0 = not alpha)')
    parser.add_argument('--current4', action='store_true',
                        help='Generate current4 JSON alongside the update file')
    parser.add_argument('--base-url', default='https://cdn.honeydrinksomewine.com',
                        help='Base URL for download link in current4')
    parser.add_argument('--threads', type=int, default=0,
                        help='Worker threads for file I/O and XZ compression (0 = auto)')
    args = parser.parse_args()

    workers = args.threads or (os.cpu_count() or 1)

    if not os.path.isdir(args.path):
        print(f"ERROR: path does not exist: {args.path}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(args.private_key):
        print(f"ERROR: private key not found: {args.private_key}", file=sys.stderr)
        sys.exit(1)

    with open(args.private_key, 'rb') as f:
        private_key_pem = f.read()

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

    result = compress_and_sign(
        bytes(inner),
        private_key_pem,
        is_windows=is_windows,
        threads=args.threads,
    )

    out_name = args.output or output_name(args.version, args.platform, args.alpha)
    with open(out_name, 'wb') as f:
        f.write(result)

    print(f"Update file '{out_name}' written successfully ({len(result)} bytes)")

    if args.current4:
        import json
        doc = {
            args.platform: {
                "stable": {
                    "released": args.version,
                    "link": f"/files/{out_name}",
                }
            }
        }
        current4_path = os.path.join(os.path.dirname(out_name) or '.', 'current4')
        with open(current4_path, 'w', encoding='utf-8') as f:
            f.write(json.dumps(doc, indent=2) + '\n')
        print(f"current4 -> '{current4_path}'")


if __name__ == '__main__':
    main()
