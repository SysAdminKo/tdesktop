#!/usr/bin/env python3
"""Extract TLS ClientHello from pcap/pcapng with TCP reassembly (no scapy)."""
from __future__ import annotations

import argparse
import collections
import struct
from pathlib import Path


def parse_pcapng(data: bytes) -> list[bytes]:
	packets: list[bytes] = []
	# Section Header Block
	if len(data) < 8 or data[0:4] != b"\x0a\x0d\x0d\x0a":
		return packets
	endian = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
	o = 0
	n = len(data)
	while o + 8 <= n:
		btype, blen = struct.unpack_from(endian + "II", data, o)
		if blen < 12 or o + blen > n:
			break
		if btype == 0x00000006:  # Enhanced Packet Block
			# iface(4) + ts(8) + caplen(4) + origlen(4) = 20 after header
			if blen >= 32:
				caplen = struct.unpack_from(endian + "I", data, o + 20)[0]
				payload_off = o + 28
				if payload_off + caplen <= o + blen - 4:
					packets.append(data[payload_off : payload_off + caplen])
		elif btype == 0x00000002:  # Packet Block (obsolete)
			if blen >= 24:
				caplen = struct.unpack_from(endian + "I", data, o + 12)[0]
				payload_off = o + 20
				if payload_off + caplen <= o + blen - 4:
					packets.append(data[payload_off : payload_off + caplen])
		elif btype == 0x0A0D0D0A:  # Section Header — endian may change
			if data[o + 8 : o + 12] == b"\x4d\x3c\x2b\x1a":
				endian = "<"
			elif data[o + 8 : o + 12] == b"\x1a\x2b\x3c\x4d":
				endian = ">"
		o += blen
	return packets


def parse_pcap(data: bytes) -> list[bytes]:
	if len(data) < 24:
		return []
	magic = data[0:4]
	if magic == b"\xd4\xc3\xb2\xa1":
		endian = "<"
	elif magic == b"\xa1\xb2\xc3\xd4":
		endian = ">"
	else:
		return []
	o = 24
	packets: list[bytes] = []
	n = len(data)
	while o + 16 <= n:
		incl = struct.unpack_from(endian + "I", data, o + 8)[0]
		o += 16
		if o + incl > n:
			break
		packets.append(data[o : o + incl])
		o += incl
	return packets


def eth_payloads(frame: bytes) -> list[tuple[bytes, bytes, int, int, int, bytes]]:
	"""Return list of (sip, dip, sport, dport, seq, tcp_payload)."""
	out: list[tuple[bytes, bytes, int, int, int, bytes]] = []
	if len(frame) < 14:
		return out
	ethertype = struct.unpack_from("!H", frame, 12)[0]
	off = 14
	# VLAN
	if ethertype == 0x8100 and len(frame) >= 18:
		ethertype = struct.unpack_from("!H", frame, 16)[0]
		off = 18
	if ethertype == 0x0800:  # IPv4
		if len(frame) < off + 20:
			return out
		vihl = frame[off]
		ihl = (vihl & 0x0F) * 4
		proto = frame[off + 9]
		sip = frame[off + 12 : off + 16]
		dip = frame[off + 16 : off + 20]
		total_len = struct.unpack_from("!H", frame, off + 2)[0]
		ip_end = off + total_len
		if proto != 6 or len(frame) < off + ihl + 20:
			return out
		tcp = frame[off + ihl : ip_end]
		if len(tcp) < 20:
			return out
		sport, dport = struct.unpack_from("!HH", tcp, 0)
		seq = struct.unpack_from("!I", tcp, 4)[0]
		doff = ((tcp[12] >> 4) & 0x0F) * 4
		payload = tcp[doff:]
		if payload:
			out.append((sip, dip, sport, dport, seq, payload))
	return out


def reassemble_streams(
	packets: list[bytes],
) -> dict[tuple, bytes]:
	# key: (sip, dip, sport, dport) client->server oriented as seen
	chunks: dict[tuple, list[tuple[int, bytes]]] = collections.defaultdict(list)
	for frame in packets:
		for sip, dip, sport, dport, seq, payload in eth_payloads(frame):
			key = (sip, dip, sport, dport)
			chunks[key].append((seq, payload))
	streams: dict[tuple, bytes] = {}
	for key, parts in chunks.items():
		parts.sort(key=lambda x: x[0])
		buf = bytearray()
		next_seq = None
		seen = set()
		for seq, payload in parts:
			if (seq, len(payload)) in seen:
				continue
			seen.add((seq, len(payload)))
			if next_seq is None:
				buf.extend(payload)
				next_seq = seq + len(payload)
			elif seq == next_seq:
				buf.extend(payload)
				next_seq = seq + len(payload)
			elif seq > next_seq:
				# gap — still append (best-effort)
				buf.extend(payload)
				next_seq = seq + len(payload)
			# else retransmission / overlap: skip
		if buf:
			streams[key] = bytes(buf)
	return streams


def find_client_hellos(data: bytes) -> list[bytes]:
	hellos: list[bytes] = []
	i = 0
	n = len(data)
	while i + 6 < n:
		if (
			data[i] == 0x16
			and data[i + 1] == 0x03
			and data[i + 2] in (0x01, 0x03)
			and data[i + 5] == 0x01
		):
			ln = (data[i + 3] << 8) | data[i + 4]
			if 200 <= ln <= 2048 and i + 5 + ln <= n:
				rec = data[i : i + 5 + ln]
				# sanity: no IP/pcap bleed markers inside
				if b"\xde\xad\xbe\xef" in rec or b"\x45\x00" in rec[100:]:
					# weak check — real CH can contain those by chance; prefer structure check later
					pass
				hellos.append(rec)
				i += 5 + ln
				continue
		i += 1
	return hellos


def validate_hello(h: bytes) -> tuple[bool, str]:
	if len(h) < 50 or h[0] != 0x16:
		return False, "not tls record"
	rec_len = (h[3] << 8) | h[4]
	if len(h) != 5 + rec_len:
		return False, f"len mismatch file={len(h)} record={5+rec_len}"
	if h[5] != 0x01:
		return False, "not clienthello"
	hs_len = (h[6] << 16) | (h[7] << 8) | h[8]
	if hs_len != len(h) - 9:
		return False, f"hs_len mismatch {hs_len} vs {len(h)-9}"
	if b"\xde\xad\xbe\xef" in h:
		return False, "contains deadbeef (pcap bleed)"
	# parse extensions without overflow
	body = h[9:]
	sid_len = body[34]
	o = 35 + sid_len
	cs_len = (body[o] << 8) | body[o + 1]
	o += 2 + cs_len
	comp_len = body[o]
	o += 1 + comp_len
	ext_len = (body[o] << 8) | body[o + 1]
	o += 2
	if ext_len != len(body) - o:
		return False, f"ext_len mismatch {ext_len} vs {len(body)-o}"
	exts = body[o:]
	i = 0
	while i + 4 <= len(exts):
		el = (exts[i + 2] << 8) | exts[i + 3]
		if i + 4 + el > len(exts):
			return False, f"extension overflow at {i}"
		i += 4 + el
	if i != len(exts):
		return False, f"extensions trailing garbage {len(exts)-i}"
	return True, "ok"


def main() -> int:
	ap = argparse.ArgumentParser()
	ap.add_argument("pcap", type=Path)
	ap.add_argument("-o", "--output", type=Path, default=None)
	ap.add_argument("--prefer-sni", default="pro.willdomarket.com")
	args = ap.parse_args()

	raw = args.pcap.read_bytes()
	if raw[0:4] == b"\x0a\x0d\x0d\x0a":
		frames = parse_pcapng(raw)
		fmt = "pcapng"
	else:
		frames = parse_pcap(raw)
		fmt = "pcap"
	print(f"{fmt}: {len(frames)} frames")

	streams = reassemble_streams(frames)
	print(f"tcp streams with payload: {len(streams)}")

	hellos: list[bytes] = []
	for blob in streams.values():
		hellos.extend(find_client_hellos(blob))
	print(f"clienthellos found: {len(hellos)}")

	valid = []
	for h in hellos:
		ok, reason = validate_hello(h)
		if ok:
			valid.append(h)
	print(f"valid clienthellos: {len(valid)}")
	if not valid:
		# show why first few failed
		for h in hellos[:5]:
			print("  reject", validate_hello(h)[1], "len", len(h))
		return 1

	sni_b = args.prefer_sni.encode()
	with_sni = [h for h in valid if sni_b in h]
	pool = with_sni if with_sni else valid
	by_len: dict[int, list[bytes]] = collections.defaultdict(list)
	for h in pool:
		by_len[len(h)].append(h)
	for length, items in sorted(by_len.items(), key=lambda x: -len(x[1]))[:10]:
		print(f"  len={length} count={len(items)} head={items[0][:12].hex()}")

	best_len = max(by_len.items(), key=lambda x: len(x[1]))[0]
	chosen = by_len[best_len][0]
	out = args.output or args.pcap.with_name("tg_hello_from_pcap.bin")
	out.write_bytes(chosen)
	ok, reason = validate_hello(chosen)
	print(f"saved {out} len={len(chosen)} valid={ok} ({reason}) sni={sni_b in chosen}")

	# summarize key_share tail for telegram check
	body = chosen[9:]
	sid = body[34]
	o = 35 + sid
	cs = (body[o] << 8) | body[o + 1]
	o += 2 + cs
	o += 1 + body[o]
	ext_len = (body[o] << 8) | body[o + 1]
	o += 2
	exts = body[o : o + ext_len]
	i = 0
	while i + 4 <= len(exts):
		et = (exts[i] << 8) | exts[i + 1]
		el = (exts[i + 2] << 8) | exts[i + 3]
		if et == 0x0033:
			ks = exts[i + 4 : i + 4 + el]
			print("key_share len", el, "tail:", ks[-40:].hex())
			print("001d0020 at", ks.find(bytes.fromhex("001d0020")))
			break
		i += 4 + el
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
