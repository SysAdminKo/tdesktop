package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func formatBytes(value int64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	div, exp := int64(unit), 0
	for n := value / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(value)/float64(div), "KMGTPE"[exp])
}

func formatDuration(seconds float64) string {
	total := int(seconds)
	if total < 60 {
		return fmt.Sprintf("%ds", total)
	}
	minutes := total / 60
	if minutes < 60 {
		return fmt.Sprintf("%dm %ds", minutes, total%60)
	}
	hours := minutes / 60
	if hours < 48 {
		return fmt.Sprintf("%dh %dm", hours, minutes%60)
	}
	days := hours / 24
	return fmt.Sprintf("%dd %dh", days, hours%24)
}

func handleStatsJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(relayStatistics.snapshot())
}

func handleStatsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(statsPageHTML))
}

const statsPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wss-relay monitor</title>
<style>
:root { color-scheme: dark; font-family: ui-sans-serif, system-ui, sans-serif; }
body { margin: 0; background: #0f1115; color: #e8eaed; }
.wrap { max-width: 1280px; margin: 0 auto; padding: 20px; }
h1 { margin: 0; font-size: 22px; }
.head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; }
.actions { display: flex; align-items: center; gap: 10px; }
.btn { background: #2a2f3a; color: #e8eaed; border: 1px solid #3c4454; border-radius: 8px; padding: 8px 14px; font-size: 13px; cursor: pointer; }
.btn:hover { background: #343b49; }
.btn:disabled { opacity: .55; cursor: not-allowed; }
.btn.danger { border-color: #9a6700; color: #fdd663; }
.action-msg { font-size: 12px; color: #9aa0a6; }
.action-msg.ok { color: #81c995; }
.action-msg.bad { color: #f28b82; }
.meta { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 20px; }
.chip { background: #171a21; border: 1px solid #2a2f3a; border-radius: 999px; padding: 5px 12px; font-size: 12px; color: #bdc1c6; }
.chip strong { color: #e8eaed; font-weight: 600; }
.chip.ok { border-color: #2e7d52; color: #81c995; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 20px; }
.card { background: #171a21; border: 1px solid #2a2f3a; border-radius: 10px; padding: 14px; }
.card.ok { border-color: #2e7d52; }
.card.warn { border-color: #9a6700; }
.card.bad { border-color: #b3261e; }
.card .label { color: #9aa0a6; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
.card .value { font-size: 22px; font-weight: 600; margin-top: 6px; line-height: 1.2; }
.card .sub { color: #9aa0a6; font-size: 11px; margin-top: 6px; line-height: 1.35; }
section { margin-top: 28px; }
section h2 { font-size: 15px; margin: 0 0 10px; color: #bdc1c6; font-weight: 600; }
.table-wrap { overflow-x: auto; border-radius: 10px; border: 1px solid #2a2f3a; }
table.stats { width: 100%; border-collapse: collapse; background: #171a21; table-layout: auto; }
table.stats th, table.stats td { padding: 10px 14px; border-bottom: 1px solid #2a2f3a; font-size: 13px; vertical-align: middle; white-space: nowrap; }
table.stats th.text, table.stats td.text { text-align: left; }
table.stats th.num, table.stats td.num { text-align: right; font-variant-numeric: tabular-nums; padding-left: 18px; }
table.stats th.text:first-child, table.stats td.text:first-child { width: 1%; padding-right: 28px; }
table.stats thead th { color: #9aa0a6; font-weight: 600; background: #12151b; position: sticky; top: 0; }
table.stats tbody tr:hover { background: #1c2029; }
table.stats tr:last-child td { border-bottom: 0; }
.util-ok { color: #81c995; }
.util-warn { color: #fdd663; }
.util-bad { color: #f28b82; }
.empty { color: #9aa0a6; padding: 16px; background: #171a21; border: 1px solid #2a2f3a; border-radius: 10px; font-size: 13px; }
</style>
</head>
<body>
<div class="wrap">
<div class="head">
<h1>wss-relay monitor</h1>
<div class="actions">
<button class="btn danger" id="restartBtn" type="button" hidden>Restart relay</button>
<span class="action-msg" id="actionMsg"></span>
</div>
</div>
<div class="meta" id="meta"></div>
<div class="grid" id="cards"></div>
<section>
<h2>Clients</h2>
<div id="clients"></div>
</section>
<section>
<h2>Abuse by IP</h2>
<div id="abuse"></div>
</section>
<section>
<h2>Upstream pool buckets</h2>
<div id="pool_buckets"></div>
</section>
<section>
<h2>Active upstream targets</h2>
<div id="upstreams"></div>
</section>
</div>
<script>
function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function fmtBytes(n) {
  const units = ['B','KiB','MiB','GiB','TiB'];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return (i ? v.toFixed(1) : v) + ' ' + units[i];
}
function fmtUptime(sec) {
  sec = Math.floor(Number(sec) || 0);
  if (sec < 60) return sec + 's';
  const m = Math.floor(sec / 60);
  if (m < 60) return m + 'm ' + (sec % 60) + 's';
  const h = Math.floor(m / 60);
  if (h < 48) return h + 'h ' + (m % 60) + 'm';
  return Math.floor(h / 24) + 'd ' + (h % 24) + 'h';
}
function fmtLimit(n) {
  if (n == null || n === '') return '?';
  return Number(n) === 0 ? '∞ (off)' : String(n);
}
function fmtCfg(n) {
  return (n == null || n === '') ? '?' : String(n);
}
function fmtRate(n) {
  const v = Number(n);
  if (!v) return '0 B/s';
  if (v >= 1024 * 1024) return (v / (1024 * 1024)).toFixed(1) + ' MiB/s';
  if (v >= 1024) return (v / 1024).toFixed(1) + ' KiB/s';
  return v.toFixed(0) + ' B/s';
}
function fmtNum(n, digits) {
  return Number(n).toFixed(digits == null ? 1 : digits);
}
function utilClass(pct) {
  pct = Number(pct) || 0;
  if (pct >= 80) return 'util-bad';
  if (pct >= 50) return 'util-warn';
  return 'util-ok';
}
function cardClass(count) {
  count = Number(count) || 0;
  if (count <= 0) return 'ok';
  if (count < 10) return 'warn';
  return 'bad';
}
function renderTable(columns, rows, emptyText) {
  if (!rows.length) return '<div class="empty">' + esc(emptyText || 'no data') + '</div>';
  let html = '<div class="table-wrap"><table class="stats"><thead><tr>';
  for (const col of columns) {
    html += '<th class="' + (col.className || 'text') + '">' + esc(col.label) + '</th>';
  }
  html += '</tr></thead><tbody>';
  for (const row of rows) {
    html += '<tr>';
    for (let i = 0; i < columns.length; i++) {
      const cell = row[i] || { text: '' };
      const base = columns[i].className || 'text';
      const extra = cell.className ? ' ' + cell.className : '';
      html += '<td class="' + base + extra + '">' + cell.text + '</td>';
    }
    html += '</tr>';
  }
  html += '</tbody></table></div>';
  return html;
}
function setActionMsg(text, kind) {
  const el = document.getElementById('actionMsg');
  el.textContent = text || '';
  el.className = 'action-msg' + (kind ? ' ' + kind : '');
}
function authToken() {
  return sessionStorage.getItem('wss-relay-token') || '';
}
function rememberAuthToken(token) {
  if (token) sessionStorage.setItem('wss-relay-token', token);
}
let restartWaiting = false;
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
async function waitForServiceAfterRestart(btn) {
  restartWaiting = true;
  setActionMsg('restart sent, waiting...', 'ok');
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    await sleep(800);
    try {
      const resp = await fetch('/stats/json', { cache: 'no-store' });
      if (!resp.ok) continue;
      const data = await resp.json();
      render(data);
      restartWaiting = false;
      btn.disabled = false;
      setActionMsg('restarted', 'ok');
      setTimeout(() => setActionMsg(''), 2000);
      return;
    } catch {}
  }
  restartWaiting = false;
  btn.disabled = false;
  setActionMsg('restart timeout — refresh page', 'bad');
}
async function restartRelay(authRequired) {
  if (!confirm('Restart wss-relay service now?')) return;
  let token = authToken();
  if (authRequired && !token) {
    token = prompt('Bearer token required to restart:');
    if (!token) return;
    rememberAuthToken(token);
  }
  const btn = document.getElementById('restartBtn');
  btn.disabled = true;
  setActionMsg('restarting...', '');
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = 'Bearer ' + token;
    const resp = await fetch('/stats/restart', { method: 'POST', headers, cache: 'no-store' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    await waitForServiceAfterRestart(btn);
  } catch (e) {
    restartWaiting = false;
    setActionMsg('restart failed: ' + e, 'bad');
    btn.disabled = false;
  }
}
function renderMeta(data) {
  const cfg = data.config || {};
  const load = data.load || {};
  const util = load.server_streams_util_pct ?? load.streams_util_pct ?? 0;
  const chips = [
    ['Updated', new Date(data.now).toLocaleString()],
    ['Uptime', fmtUptime(data.uptime_sec)],
    ['Capacity', (load.streams_capacity || 0) + ' streams'],
    ['Util', util + '%', utilClass(util)],
    ['Streams/tunnel', fmtCfg(cfg.max_streams)],
    ['Tunnels/IP', fmtLimit(cfg.max_tunnels_per_ip)],
    ['Auth', cfg.auth_enabled ? 'on' : 'off', cfg.auth_enabled ? 'ok' : ''],
  ];
  document.getElementById('meta').innerHTML = chips.map(([k, v, cls]) =>
    '<span class="chip' + (cls ? ' ' + cls : '') + '">' + esc(k) + ': <strong>' + esc(v) + '</strong></span>'
  ).join('');
}
function render(data) {
  const control = data.control || {};
  const restartBtn = document.getElementById('restartBtn');
  if (control.restart_enabled) {
    restartBtn.hidden = false;
    restartBtn.onclick = () => restartRelay(!!control.auth_required);
  } else {
    restartBtn.hidden = true;
  }
  const load = data.load || {};
  const rates = data.rates || {};
  renderMeta(data);
  const util = load.server_streams_util_pct ?? load.streams_util_pct ?? 0;
  const cards = [
    ['Mux tunnels', data.mux_tunnels + ' (peak ' + data.mux_tunnels_peak + ')', 'total ' + data.mux_tunnels_total + ' · ' + fmtNum(rates.tunnels_opened_per_min, 1) + '/min', ''],
    ['Mux streams', data.mux_streams + ' (peak ' + data.mux_streams_peak + ')', 'server ' + util + '% · ' + fmtNum(rates.streams_opened_per_min, 1) + '/min', util >= 80 ? 'warn' : ''],
    ['To Telegram', fmtBytes(data.bytes_to_upstream), fmtRate(rates.bytes_to_upstream_per_sec), ''],
    ['From Telegram', fmtBytes(data.bytes_from_upstream), fmtRate(rates.bytes_from_upstream_per_sec), ''],
    ['Dial', data.mux_open_dial_ms_avg + ' / ' + data.mux_open_dial_ms_p95 + ' / ' + data.mux_open_dial_ms_max + ' ms', 'avg / p95 / max · count ' + data.mux_open_count + ' · slow ' + data.mux_open_slow, data.mux_open_slow > 0 ? 'warn' : 'ok'],
    ['Pool hit', (data.upstream_pool_hit_pct || 0) + '%', 'hits ' + (data.upstream_pool_hits || 0) + ' · miss ' + (data.upstream_pool_misses || 0) + ' · dial err ' + (data.upstream_pool_dial_errors || 0), (data.upstream_pool_dial_errors || 0) > 0 ? 'warn' : 'ok'],
    ['Write wait', data.mux_write_wait_us_avg + ' / ' + data.mux_write_wait_us_p95 + ' / ' + data.mux_write_wait_us_max + ' µs', 'avg / p95 / max', ''],
    ['Upstream errors', String(data.upstream_dial_errors), 'blocked ' + data.upstream_blocked + ' · stall ' + data.mux_upstream_read_stall + ' · rotate ' + data.mux_upstream_read_stall_rotate, cardClass(data.upstream_dial_errors + data.upstream_blocked + data.mux_upstream_read_stall_rotate)],
    ['Open fails', String(data.mux_open_fail_dial), 'bad ' + data.mux_open_bad + ' · limit ' + data.mux_open_limit, cardClass(data.mux_open_fail_dial + data.mux_open_bad + data.mux_open_limit)],
    ['429 limits', String(data.tunnel_limit_rejected), 'max ' + (load.tunnels_per_ip_max || 0) + ' tunnels/ip · avg ' + fmtNum(load.tunnels_per_ip_avg || 0, 1), cardClass(data.tunnel_limit_rejected)],
    ['WS / auth', String(data.auth_failures), 'upgrade ' + data.ws_upgrade_failures + ' · decode ' + data.mux_decode_errors, cardClass(data.auth_failures + data.ws_upgrade_failures + data.mux_decode_errors)],
    ['Tunnel drops', String(data.tunnels_ended_with_streams), 'idle ' + data.mux_stream_idle_expired + ' · graceful ' + data.mux_streams_closed_graceful, cardClass(data.tunnels_ended_with_streams)],
  ];
  document.getElementById('cards').innerHTML = cards.map(([label, value, sub, cls]) =>
    '<div class="card' + (cls ? ' ' + cls : '') + '"><div class="label">' + esc(label) + '</div><div class="value">' + esc(value) + '</div><div class="sub">' + esc(sub) + '</div></div>'
  ).join('');
  document.getElementById('clients').innerHTML = renderTable(
    [
      { label: 'Client IP', className: 'text' },
      { label: 'Tunnels', className: 'num' },
      { label: 'Streams', className: 'num' },
      { label: 'Peak', className: 'num' },
      { label: 'Util', className: 'num' },
      { label: 'Up/s', className: 'num' },
      { label: 'Down/s', className: 'num' },
      { label: 'Total up', className: 'num' },
      { label: 'Total down', className: 'num' },
    ],
    (data.clients || []).map(c => {
      const u = c.streams_util_pct || 0;
      return [
        { text: esc(c.ip) },
        { text: String(c.active_tunnels) },
        { text: String(c.active_streams) },
        { text: String(c.streams_peak || 0) },
        { text: String(u) + '%', className: utilClass(u) },
        { text: fmtRate((c.rates && c.rates.bytes_to_upstream_per_sec) || 0) },
        { text: fmtRate((c.rates && c.rates.bytes_from_upstream_per_sec) || 0) },
        { text: fmtBytes(c.bytes_to_upstream) },
        { text: fmtBytes(c.bytes_from_upstream) },
      ];
    }),
    'no active clients'
  );
  document.getElementById('abuse').innerHTML = renderTable(
    [
      { label: 'Client IP', className: 'text' },
      { label: 'Auth fail', className: 'num' },
      { label: '429', className: 'num' },
      { label: 'Blocked', className: 'num' },
    ],
    (data.abuse_by_ip || []).map(a => [
      { text: esc(a.ip) },
      { text: String(a.auth_failures) },
      { text: String(a.tunnel_limit_rejected) },
      { text: String(a.upstream_blocked) },
    ]),
    'no abuse events recorded'
  );
  document.getElementById('pool_buckets').innerHTML = renderTable(
    [
      { label: 'Egress', className: 'text' },
      { label: 'Target', className: 'text' },
      { label: 'Live', className: 'num' },
      { label: 'Size', className: 'num' },
      { label: 'Idle', className: 'num' },
      { label: 'Win 5s %', className: 'num' },
      { label: 'Win 5s h/m', className: 'num' },
      { label: 'Total hit%', className: 'num' },
      { label: 'Total h/m', className: 'num' },
      { label: 'Last', className: 'text' },
    ],
    (data.pool_buckets || []).map(b => [
      { text: esc(b.egress || 'default') },
      { text: esc(b.target) },
      { text: b.active ? 'yes' : 'no' },
      { text: b.active ? String(b.size) : '—' },
      { text: b.active ? String(b.idle) : '—' },
      { text: b.active ? String(b.window_hit_pct || 0) + '%' : '—' },
      { text: b.active ? (b.window_hits || 0) + ' / ' + (b.window_misses || 0) : '—' },
      { text: String(b.total_hit_pct || 0) + '%' },
      { text: (b.total_hits || 0) + ' / ' + (b.total_misses || 0) },
      { text: b.last_activity ? esc(b.last_activity.slice(11, 19) + 'Z') : '—' },
    ]),
    'no pool bucket history'
  );
  document.getElementById('upstreams').innerHTML = renderTable(
    [
      { label: 'Target', className: 'text' },
      { label: 'DC', className: 'text' },
      { label: 'Streams', className: 'num' },
      { label: 'Up', className: 'num' },
      { label: 'Down', className: 'num' },
      { label: 'Dial err', className: 'num' },
      { label: 'Open avg ms', className: 'num' },
      { label: 'Pool hit%', className: 'num' },
      { label: 'Pool h/m', className: 'num' },
    ],
    (data.upstreams || []).map(u => [
      { text: esc(u.target) },
      { text: esc(u.dc || '—') },
      { text: String(u.active_streams) },
      { text: fmtBytes(u.bytes_to_upstream) },
      { text: fmtBytes(u.bytes_from_upstream) },
      { text: String(u.dial_errors), className: u.dial_errors ? 'util-bad' : '' },
      { text: String(u.open_dial_ms_avg || 0) },
      { text: (u.pool_hit_pct || 0) + '%' },
      { text: (u.pool_hits || 0) + ' / ' + (u.pool_misses || 0) },
    ]),
    'no active upstream connections'
  );
}
async function refresh() {
  if (restartWaiting) return;
  try {
    const resp = await fetch('/stats/json', { cache: 'no-store' });
    render(await resp.json());
  } catch (e) {
    document.getElementById('meta').innerHTML = '<span class="chip bad">refresh failed: ' + esc(e) + '</span>';
  }
}
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>`

func statsPathEnabled(path string) bool {
	path = strings.TrimSpace(path)
	return path != "" && path != "-"
}
