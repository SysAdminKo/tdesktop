#!/usr/bin/env python3
"""
Update format v2 (Telegram Desktop 7.3+): TDUP envelope + Ed25519.

Mirrors Telegram/SourceFiles/core/update_verify.cpp. Envelope layout,
all integers little-endian:

    "TDUP" | u32 format=2 | u8 channel | u8 os | u8 arch
    | u64 version (base << 32 | counter) | u64 created
    | u32 len + manifest JSON                   <- end of signed region
    | u32 len + manifest root signature
    | u32 count, count * (u32 len + key id, u32 len + signature)
    | u32 len + payload

Each signature covers signed_region || SHA256(payload). The payload keeps
the v1 layout without RSA signature and SHA-1:
[lzma props on Windows,] int32 original size, compressed bytes.

Trust files embedded into the client at build time live in
Telegram/Resources/update/: root-public.pem, manifest.min.json,
manifest.sig. Private keys live in tools/Packer/keys/ (gitignored).
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

BASE_DIR = Path(__file__).resolve().parent
REPO_ROOT = BASE_DIR.parent.parent
TRUST_DIR = REPO_ROOT / 'Telegram' / 'Resources' / 'update'
KEYS_DIR = BASE_DIR / 'keys'

ROOT_PUBLIC_FILE = TRUST_DIR / 'root-public.pem'
MANIFEST_FILE = TRUST_DIR / 'manifest.min.json'
MANIFEST_SIG_FILE = TRUST_DIR / 'manifest.sig'
ROOT_PRIVATE_FILE = KEYS_DIR / 'v2_root_private.pem'

MAGIC = b'TDUP'
FORMAT = 2

CHANNELS = {
    'stable': 0,
    'beta': 1,
    'canary-public': 2,
    'canary-private': 3,
}

OS_NAMES = {0: 'win', 1: 'mac', 2: 'linux'}
ARCH_NAMES = {0: 'x86', 1: 'x64', 2: 'arm'}

# Platform::AutoUpdateKey() -> (os, arch), see TargetFromPlatformKey().
PLATFORM_TARGETS = {
    'win': (0, 0),
    'win64': (0, 1),
    'winarm': (0, 2),
    'mac': (1, 1),
    'armac': (1, 2),
    'linux': (2, 1),
}


class UpdateV2Error(Exception):
    pass


def release_key_file(key_id: str) -> Path:
    return KEYS_DIR / f'v2_release_{key_id}.pem'


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def from_b64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def generate_key() -> ECC.EccKey:
    return ECC.generate(curve='ed25519')


def load_private_key(path: Path) -> ECC.EccKey:
    if not path.is_file():
        raise UpdateV2Error(f'private key not found: {path}')
    key = ECC.import_key(path.read_bytes())
    if key.curve != 'Ed25519' or not key.has_private():
        raise UpdateV2Error(f'not an Ed25519 private key: {path}')
    return key


def save_private_key(key: ECC.EccKey, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.export_key(format='PEM').encode('ascii') + b'\n')


def public_pem(key: ECC.EccKey) -> bytes:
    pem = key.public_key().export_key(format='PEM')
    return pem.encode('ascii') + b'\n'


def public_raw(key: ECC.EccKey) -> bytes:
    return key.public_key().export_key(format='raw')


def sign(key: ECC.EccKey, message: bytes) -> bytes:
    return eddsa.new(key, 'rfc8032').sign(message)


def verify(public_key: ECC.EccKey, message: bytes, signature: bytes) -> bool:
    try:
        eddsa.new(public_key, 'rfc8032').verify(message, signature)
        return True
    except ValueError:
        return False


def manifest_bytes(manifest: dict) -> bytes:
    return json.dumps(manifest, separators=(',', ':')).encode('utf-8')


@dataclass
class Trust:
    root_pem: bytes
    manifest: bytes
    manifest_sig: bytes
    parsed: dict


def load_trust() -> Trust:
    for path in (ROOT_PUBLIC_FILE, MANIFEST_FILE, MANIFEST_SIG_FILE):
        if not path.is_file():
            raise UpdateV2Error(f'trust file not found: {path}')
    trust = Trust(
        root_pem=ROOT_PUBLIC_FILE.read_bytes(),
        manifest=MANIFEST_FILE.read_bytes(),
        manifest_sig=MANIFEST_SIG_FILE.read_bytes(),
        parsed={},
    )
    root = ECC.import_key(trust.root_pem)
    if not verify(root, trust.manifest, trust.manifest_sig):
        raise UpdateV2Error('manifest root signature does not verify')
    trust.parsed = json.loads(trust.manifest)
    return trust


def channel_key_id(manifest: dict, channel: str) -> str:
    groups = manifest.get('channels', {}).get(channel)
    if not groups or len(groups) != 1 or not groups[0]:
        raise UpdateV2Error(
            f"channel '{channel}' must have exactly one key group")
    return groups[0][0]


def target_for(platform: str) -> tuple[int, int]:
    if platform not in PLATFORM_TARGETS:
        raise UpdateV2Error(f'unknown platform: {platform}')
    return PLATFORM_TARGETS[platform]


def file_name(platform: str, channel: str, base_version: int) -> str:
    os_id, arch_id = target_for(platform)
    suffix = '-beta' if channel == 'beta' else ''
    return (f'td-update-{OS_NAMES[os_id]}-{ARCH_NAMES[arch_id]}'
            f'-{base_version}{suffix}')


def make_version(base: int, counter: int = 0) -> int:
    return (base << 32) | counter


def _signed_region(
        channel: int,
        target: tuple[int, int],
        version: int,
        created: int,
        manifest: bytes) -> bytes:
    return (MAGIC
            + struct.pack('<IBBBQQI', FORMAT, channel, target[0], target[1],
                          version, created, len(manifest))
            + manifest)


def _tail(
        manifest_sig: bytes,
        signatures: list[tuple[bytes, bytes]],
        payload: bytes) -> bytes:
    result = bytearray()
    result += struct.pack('<I', len(manifest_sig)) + manifest_sig
    result += struct.pack('<I', len(signatures))
    for key_id, signature in signatures:
        result += struct.pack('<I', len(key_id)) + key_id
        result += struct.pack('<I', len(signature)) + signature
    result += struct.pack('<I', len(payload)) + payload
    return bytes(result)


def build_envelope(
        trust: Trust,
        key: ECC.EccKey,
        key_id: str,
        channel: str,
        platform: str,
        version: int,
        created: int,
        payload: bytes) -> bytes:
    region = _signed_region(
        CHANNELS[channel],
        target_for(platform),
        version,
        created,
        trust.manifest)
    signature = sign(key, region + hashlib.sha256(payload).digest())
    return region + _tail(
        trust.manifest_sig,
        [(key_id.encode('ascii'), signature)],
        payload)


@dataclass
class Envelope:
    channel: int
    target: tuple[int, int]
    version: int
    created: int
    manifest: bytes
    manifest_sig: bytes
    signatures: list[tuple[bytes, bytes]]
    payload: bytes
    signed_region: bytes


def parse_envelope(data: bytes) -> Envelope:
    offset = 0

    def take(count: int) -> bytes:
        nonlocal offset
        if count > len(data) - offset:
            raise UpdateV2Error('truncated envelope')
        chunk = data[offset:offset + count]
        offset += count
        return chunk

    def u32() -> int:
        return struct.unpack('<I', take(4))[0]

    if take(4) != MAGIC:
        raise UpdateV2Error('bad envelope magic')
    if u32() != FORMAT:
        raise UpdateV2Error('bad envelope format')
    channel, os_id, arch_id = take(3)
    version, created = struct.unpack('<QQ', take(16))
    manifest = take(u32())
    signed_region = data[:offset]
    manifest_sig = take(u32())
    signatures = []
    for _ in range(u32()):
        key_id = take(u32())
        signatures.append((key_id, take(u32())))
    payload = take(u32())
    if offset != len(data):
        raise UpdateV2Error('trailing bytes after payload')
    return Envelope(channel, (os_id, arch_id), version, created, manifest,
                    manifest_sig, signatures, payload, signed_region)


def verify_package(
        data: bytes,
        trust: Trust,
        channel: str,
        platform: str) -> None:
    """Re-runs the client checks over a finished package."""
    envelope = parse_envelope(data)
    if envelope.target != target_for(platform):
        raise UpdateV2Error('package target mismatch')
    if envelope.channel != CHANNELS[channel]:
        raise UpdateV2Error('package channel mismatch')
    root = ECC.import_key(trust.root_pem)
    if not verify(root, envelope.manifest, envelope.manifest_sig):
        raise UpdateV2Error('carried manifest root signature is bad')
    manifest = json.loads(envelope.manifest)
    keys = {entry['id']: entry for entry in manifest['keys']}
    revoked = set(manifest.get('revoked', []))
    signing_input = (envelope.signed_region
                     + hashlib.sha256(envelope.payload).digest())
    for group in manifest['channels'][channel]:
        satisfied = False
        for key_id in group:
            entry = keys.get(key_id)
            if key_id in revoked or not entry or entry['alg'] != 'Ed25519':
                continue
            public = eddsa.import_public_key(from_b64url(entry['x']))
            for sig_id, signature in envelope.signatures:
                if (sig_id.decode('ascii') == key_id
                        and verify(public, signing_input, signature)):
                    satisfied = True
                    break
            if satisfied:
                break
        if not satisfied:
            raise UpdateV2Error('no valid signature for a required group')
