#!/usr/bin/env python3
import struct
import sys
from collections import defaultdict
from datetime import datetime

DC_IPS = [
    "149.154.167.35",
    "149.154.167.222",
    "149.154.167.41",
    "149.154.167.255",
]
RELAY = "31.76.21.175"


def parse_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        le = magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            if le:
                ts_sec, ts_usec, incl, orig = struct.unpack("<IIII", ph)
            else:
                ts_sec, ts_usec, incl, orig = struct.unpack(">IIII", ph)
            data = f.read(incl)
            if len(data) < incl:
                break
            yield ts_sec + ts_usec / 1_000_000, data


def ip4(packet, off):
    if len(packet) < off + 20:
        return None, 0, 0, 0
    ver = packet[off] >> 4
    if ver != 4:
        return None, 0, 0, 0
    ihl = (packet[off] & 0xF) * 4
    if len(packet) < off + ihl:
        return None, 0, 0, 0
    proto = packet[off + 9]
    src = ".".join(str(packet[off + 12 + i]) for i in range(4))
    dst = ".".join(str(packet[off + 16 + i]) for i in range(4))
    return proto, src, dst, off + ihl


def tcp_payload_len(packet, off):
    if len(packet) < off + 20:
        return 0, 0, False, False
    data_off = ((packet[off + 12] >> 4) & 0xF) * 4
    flags = packet[off + 13]
    seq = struct.unpack(">I", packet[off + 4 : off + 8])[0]
    payload = max(0, len(packet) - off - data_off)
    syn = bool(flags & 0x02)
    rst = bool(flags & 0x04)
    return payload, seq, syn, rst


def analyze(path):
    flows_in = defaultdict(list)
    flows_out = defaultdict(list)
    stats = {ip: {"in_pkts": 0, "in_bytes": 0, "out_pkts": 0, "out_bytes": 0, "rst": 0, "syn": 0} for ip in DC_IPS}

    for ts, raw in parse_pcap(path):
        if len(raw) < 14:
            continue
        eth_type = struct.unpack(">H", raw[12:14])[0]
        off = 14
        if eth_type == 0x8100:
            off = 18
        proto, src, dst, off = ip4(raw, off)
        if proto != 6:
            continue
        sport = struct.unpack(">H", raw[off : off + 2])[0]
        dport = struct.unpack(">H", raw[off + 2 : off + 4])[0]
        if sport != 443 and dport != 443:
            continue
        payload, seq, syn, rst = tcp_payload_len(raw, off)
        dc = None
        direction = None
        for ip in DC_IPS:
            if src == ip and dst == RELAY:
                dc = ip
                direction = "in"
                break
            if dst == ip and src == RELAY:
                dc = ip
                direction = "out"
                break
        if not dc:
            continue
        st = stats[dc]
        if rst:
            st["rst"] += 1
        if syn:
            st["syn"] += 1
        if direction == "in":
            st["in_pkts"] += 1
            st["in_bytes"] += payload
            if payload > 0:
                flows_in[dc].append((ts, payload, seq))
        else:
            st["out_pkts"] += 1
            st["out_bytes"] += payload
            if payload > 0:
                flows_out[dc].append((ts, payload))

    print(f"pcap: {path}")
    for ip in DC_IPS:
        st = stats[ip]
        print(f"\n=== {ip} ===")
        print(
            f"  in:  {st['in_pkts']} pkts, {st['in_bytes']} payload bytes"
        )
        print(
            f"  out: {st['out_pkts']} pkts, {st['out_bytes']} payload bytes"
        )
        print(f"  syn={st['syn']} rst={st['rst']}")
        events = flows_in[ip]
        if len(events) < 2:
            print("  gaps: insufficient inbound data")
            continue
        gaps = []
        for i in range(1, len(events)):
            gaps.append(events[i][0] - events[i - 1][0])
        gaps.sort()
        g1 = sum(1 for g in gaps if g >= 1.0)
        g3 = sum(1 for g in gaps if g >= 3.0)
        g5 = sum(1 for g in gaps if g >= 5.0)
        avg = sum(gaps) / len(gaps)
        p95 = gaps[int(len(gaps) * 0.95)] if gaps else 0
        mx = gaps[-1]
        print(
            f"  inbound data gaps: n={len(gaps)} avg={avg:.3f}s p95={p95:.3f}s max={mx:.3f}s"
        )
        print(f"  gaps>=1s={g1} >=3s={g3} >=5s={g5}")
        if g3:
            print("  top gaps >=3s:")
            shown = 0
            for i in range(1, len(events)):
                g = events[i][0] - events[i - 1][0]
                if g >= 3.0 and shown < 5:
                    t0 = datetime.fromtimestamp(events[i - 1][0]).strftime("%H:%M:%S")
                    t1 = datetime.fromtimestamp(events[i][0]).strftime("%H:%M:%S")
                    print(f"    {t0} -> {t1}  {g:.2f}s  after {events[i-1][1]}B")
                    shown += 1


if __name__ == "__main__":
    for p in sys.argv[1:]:
        analyze(p)
