# ADR-001: Mux Control Plane vs Data Plane

| Field | Value |
|-------|-------|
| Status | Accepted — Phase 1 + temporary plain client/relay |
| Date | 2026-07-27 |
| Context | `wss-mux` client hub + `wss-relay` |
| Relates | [WSS-MUX.MD](WSS-MUX.MD) |

---

## 1. Context

Current WSS-MUX:

```
DownloadManager / MTP sessions
  → MuxStreamSocket
    → WssMuxHub (pick, affinity, elastic, pending opens, reconnect)
      → WssMuxTunnel (one WS = Open/Ok/Fail/Close/Ping + Data)
        → Relay muxSession → N TCP to DC
```

Control frames (`Open` / `OpenOk` / `OpenFail` / `Close` / `Ping`) and bulk `Data` share the same WebSocket byte stream. The hub also owns tunnel lifecycle, VIP RR, affinity, elastic scale, and stream routing on the hot path.

Observed failure modes (media download):

1. **Client orchestration thrash** — elastic desired, wait-for-download-tunnels, Limit backoff made UX worse; rolled back.
2. **Open vs Limit races** — relay needed reserve-before-dial; client crutches did not fix root.
3. **Upstream stalls** — many parallel TCPs to the same DC IP; relay congestion hacks (`upstream-target-max`) caused OpenFail Limit storms.
4. **Spec conflation** — docs still say “fixed 9 tunnels”; runtime mixes `kDefaultTunnelCount=9`, `kBaseTunnelCount=3`, elastic toward target=4.

Tuning constants no longer moves the needle. Roles of control vs data are unclear.

---

## 2. Decision

Adopt a **phased split of control plane and data plane**. Do not replace mux with plain WSS or QUIC in this ADR.

### Phase 0 — Roles (ADR contract, no wire change)

| Role | Owner | Responsibility |
|------|-------|----------------|
| Main tunnel | `t0` only (`affinity < 0`) | Interactive / main MTP; never mixed with download affinity slots |
| Download/upload tunnels | `t1…` | Media streams only |
| Parallelism source | `DownloadManager` / upload | How many MTP sessions (streams) to open |
| Routing | Hub data path | Bind stream → already-chosen tunnel; send/receive Data |
| Tunnel lifecycle + Open/Close | Hub control path | Connect, reconnect, Open/Ok/Fail, Close, budgets |
| Relay | Dumb pipe | Dial, reserve stream, forward bytes; no client-side congestion policy |

**Baseline topology (target after Phase 1):** fixed **3** tunnels (`t0` + 2 download), `cap=16` streams/tunnel. Elastic off by default until a measured need returns.

### Phase 1 — Logical split on client (same wire `/ws/mux`)

Refactor hub into two faces (names illustrative):

```
MuxControl
  Acquire(stream) → assign streamId, pick tunnel, enqueue Open
  OnOpenOk / OnOpenFail / OnClose
  Tunnel up/down, reconnect, VIP pick at tunnel start
  Stream budget (per tunnel / optional per DC)

MuxData
  Send(streamId, bytes) / Recv → tunnel already bound
  No pickTunnel / elastic / pending-open logic on send path
```

API sketch for MTProto / `MuxStreamSocket`:

```
Acquire → (pending)
OpenAck(tunnelId, streamId) → BindTunnel
Data… 
Close → Unregister
```

Wire protocol **unchanged** (`tdesktop-mux/1`). Relay keeps single WS with existing frame types. Keep proven pieces: VIP RR at tunnel start, idle-only IP sync, flush pending opens on connect only, reserve-before-dial on relay.

### Phase 2 — Optional physical control channel (only if Phase 1 insufficient)

If Open/Fail still starve behind multi‑MB Data on one WS:

```
/ws/mux-ctrl   — Open, OpenOk, OpenFail, Close, Ping, Assign(tunnel)
/ws/mux        — Data (+ optional Close) on N data tunnels
```

`OpenOk` (or Assign) carries `tunnel_id` / egress hint so the client binds the stream to a data tunnel. Subprotocol bump or second subprotocol (`tdesktop-mux-ctrl/1`) required.

**Gate for Phase 2:** measured evidence that control latency / OpenFail correlates with DATA queue depth on the same WS after Phase 1, not only upstream DC stalls.

---

## 3. Consequences

### Positive

- Clear ownership: DownloadManager floods streams; hub does not “heal” by elastic/wait gates.
- Hot path shrinks: Data path cannot thrash tunnel count.
- Easier to reason about OpenFail Limit vs upstream stall.
- Phase 2 becomes an incremental add-on, not a rewrite.

### Negative / cost

- Phase 1: non-trivial hub refactor; risk of regressions in main-session affinity and reconnect grace.
- Phase 2: second handshake/TLS (or shared session design), dual reconnect semantics, relay dual listener.
- Docs and settings must stop saying “always 9 tunnels” if baseline is 3.

### Explicit non-goals (this ADR)

- DNS IP cache in settings
- Speculative 9 tunnels / traffic-based pick as default
- Client OpenFail Limit backoff + forced reconnect
- Relay `upstream-target-max` / global stream slot queues that fill before dial
- Client wait for N download tunnels before first Open

Reintroduce only with new evidence and a new ADR amendment.

---

## 4. Alternatives considered

| Option | Verdict |
|--------|---------|
| Keep tuning `kBase` / elastic / caps | Rejected as primary strategy — already thrashed and rolled back |
| One WS, many streams, no multi-tunnel | Rejected for now — loses VIP diversity / failover |
| Plain WSS (1 WS = 1 TCP) | Rejected — returns TLS storm and path we already left |
| QUIC / HTTP/3 streams | Deferred — wrong cost/benefit for tdesktop fork |
| Congestion policy on relay (target-max) | Rejected — caused Limit storms; relay stays pipe |
| Physical ctrl channel first | Deferred — try logical split (Phase 1) before wire split |

---

## 5. Implementation order (suggested)

1. Freeze roles in this ADR; update [WSS-MUX.MD](WSS-MUX.MD) § terminology for Control vs Data. **Done**
2. Hub: extract control vs data call paths; disable elastic; fixed 3-tunnel start. **Done** (`sendBoundData`, `kFixedTunnelCount=3`)
3. Align DownloadManager initial sessions with fixed download tunnel capacity (no hub wait-gate). — `kWssInitialDownloadSessions=3` kept (fits 2 download tunnels × cap 16)
4. Measure: Open RTT, OpenFail reasons, WSS read gap, relay `mux_upstream_read_stall`.
5. Only then: Phase 2 wire split if control still HOL-blocked by Data.

---

## 6. Success metrics

| Metric | Phase 1 target |
|--------|----------------|
| OpenFail Limit rate | Near zero under normal media load (reserve-before-dial held) |
| Elastic add/remove | Zero when elastic off |
| Media download UX | No worse than current best baseline (3 tunnels, cap 16) |
| Main session | Unaffected by download stream count (t0 isolation) |
| Phase 2 trigger | Control Open RTT p95 rises with DATA queue, not with DC stall alone |

---

## 7. Status notes

- **Accepted** — Phase 1 on client: fixed 3 tunnels (`kFixedTunnelCount`), elastic removed, `SendData` → `sendBoundData` (bound tunnel only), Open/Close remain control path.
- **Temporary plain baseline:** client `MTP::kWssPlainTransfer`; relay `-plain` + async per-stream `toDC` queue, fair DATA cap (plain=4), DATA enqueue waits on backpressure (no 5s kill). Debug: plain still logs upstream read stall/gap + write-queue/fairness waits (no rotate). Gap logs split `read_wait_ms` / `prev_write_frame_ms` / `cause=` / `toDC_q` / egress; also `toDC enqueue block`, slow `toDC write`, slow `WriteMessage`. Client logs `Download slow/stall` even in plain via `wssMuxProxyActive()`, restart reasons, mux drop-data.
- Phase 2 (physical `/ws/mux-ctrl`) not started; gate unchanged.
- Relay production: reserve-before-dial **on**, `upstream-target-max` **off**, `-plain` **on**, async ingress **on**, DATA flush-before-CLOSE **on**.
- Verify with `DEBUG_LOG` + relay metrics after rebuild.
