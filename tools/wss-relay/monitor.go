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
.wrap { max-width: 1200px; margin: 0 auto; padding: 20px; }
h1 { margin: 0 0 8px; font-size: 22px; }
.meta { color: #9aa0a6; font-size: 13px; margin-bottom: 20px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }
.card { background: #171a21; border: 1px solid #2a2f3a; border-radius: 10px; padding: 14px; }
.card .label { color: #9aa0a6; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.card .value { font-size: 24px; font-weight: 600; margin-top: 6px; }
.card .sub { color: #9aa0a6; font-size: 12px; margin-top: 4px; }
section { margin-top: 24px; }
section h2 { font-size: 16px; margin: 0 0 10px; }
table { width: 100%; border-collapse: collapse; background: #171a21; border: 1px solid #2a2f3a; border-radius: 10px; overflow: hidden; }
th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #2a2f3a; font-size: 13px; }
th { color: #9aa0a6; font-weight: 600; background: #12151b; }
tr:last-child td { border-bottom: 0; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.empty { color: #9aa0a6; padding: 16px; }
</style>
</head>
<body>
<div class="wrap">
<h1>wss-relay monitor</h1>
<div class="meta" id="meta">loading...</div>
<div class="grid" id="cards"></div>
<section>
<h2>Clients</h2>
<div id="clients"></div>
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
function renderTable(headers, rows) {
  if (!rows.length) return '<div class="empty">no data</div>';
  let html = '<table><thead><tr>';
  for (const h of headers) html += '<th>' + esc(h) + '</th>';
  html += '</tr></thead><tbody>';
  for (const row of rows) {
    html += '<tr>';
    for (const cell of row) html += '<td class="' + (cell.className || '') + '">' + cell.text + '</td>';
    html += '</tr>';
  }
  html += '</tbody></table>';
  return html;
}
function render(data) {
  document.getElementById('meta').textContent =
    'updated ' + data.now + ' · uptime ' + Math.floor(data.uptime_sec) + 's';
  const cards = [
    ['Mux tunnels', data.mux_tunnels, 'total ' + data.mux_tunnels_total],
    ['Mux streams', data.mux_streams, 'opened ' + data.mux_streams_opened + ', closed ' + data.mux_streams_closed + ' (graceful ' + data.mux_streams_closed_graceful + ', idle ' + data.mux_stream_idle_expired + ')'],
    ['To Telegram', fmtBytes(data.bytes_to_upstream), 'from clients'],
    ['From Telegram', fmtBytes(data.bytes_from_upstream), 'to clients'],
    ['Dial errors', data.upstream_dial_errors, 'blocked ' + data.upstream_blocked],
    ['429 limits', data.tunnel_limit_rejected, 'open limit ' + data.mux_open_limit],
  ];
  document.getElementById('cards').innerHTML = cards.map(([label, value, sub]) =>
    '<div class="card"><div class="label">' + esc(label) + '</div><div class="value">' + esc(value) + '</div><div class="sub">' + esc(sub) + '</div></div>'
  ).join('');
  document.getElementById('clients').innerHTML = renderTable(
    ['Client IP', 'Tunnels', 'Streams', 'Up', 'Down'],
    data.clients.map(c => [
      { text: esc(c.ip) },
      { text: String(c.active_tunnels), className: 'num' },
      { text: String(c.active_streams), className: 'num' },
      { text: fmtBytes(c.bytes_to_upstream), className: 'num' },
      { text: fmtBytes(c.bytes_from_upstream), className: 'num' },
    ])
  );
  document.getElementById('upstreams').innerHTML = renderTable(
    ['Target', 'Streams'],
    data.upstreams.map(u => [
      { text: esc(u.target) },
      { text: String(u.active_streams), className: 'num' },
    ])
  );
}
async function refresh() {
  try {
    const resp = await fetch('/stats/json', { cache: 'no-store' });
    render(await resp.json());
  } catch (e) {
    document.getElementById('meta').textContent = 'refresh failed: ' + e;
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
