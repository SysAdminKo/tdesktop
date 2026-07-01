package main

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
)

func handleMetrics(w http.ResponseWriter, snapshot statsSnapshot) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	var b strings.Builder
	writeMetricGauge := func(name, help string, value float64) {
		b.WriteString("# HELP ")
		b.WriteString(name)
		b.WriteString(" ")
		b.WriteString(help)
		b.WriteString("\n# TYPE ")
		b.WriteString(name)
		b.WriteString(" gauge\n")
		b.WriteString(name)
		b.WriteString(" ")
		b.WriteString(formatPromFloat(value))
		b.WriteString("\n")
	}
	writeMetricCounter := func(name, help string, value float64) {
		b.WriteString("# HELP ")
		b.WriteString(name)
		b.WriteString(" ")
		b.WriteString(help)
		b.WriteString("\n# TYPE ")
		b.WriteString(name)
		b.WriteString(" counter\n")
		b.WriteString(name)
		b.WriteString(" ")
		b.WriteString(formatPromFloat(value))
		b.WriteString("\n")
	}
	writeMetricGauge("wss_relay_uptime_seconds", "Process uptime in seconds", snapshot.UptimeSec)
	writeMetricGauge("wss_relay_mux_tunnels", "Active mux tunnels", float64(snapshot.MuxTunnels))
	writeMetricGauge("wss_relay_mux_streams", "Active mux streams", float64(snapshot.MuxStreams))
	writeMetricGauge("wss_relay_mux_tunnels_peak", "Peak mux tunnels since start", float64(snapshot.MuxTunnelsPeak))
	writeMetricGauge("wss_relay_mux_streams_peak", "Peak mux streams since start", float64(snapshot.MuxStreamsPeak))
	writeMetricGauge("wss_relay_streams_capacity", "Max streams capacity (tunnels * max_streams)", float64(snapshot.Load.StreamsCapacity))
	writeMetricGauge("wss_relay_streams_util_pct", "Active streams as percent of capacity", float64(snapshot.Load.ServerStreamsUtilPct))
	writeMetricGauge("wss_relay_bytes_to_upstream_per_sec", "Client to Telegram throughput", snapshot.Rates.BytesToUpstreamPerSec)
	writeMetricGauge("wss_relay_bytes_from_upstream_per_sec", "Telegram to client throughput", snapshot.Rates.BytesFromUpstreamPerSec)
	writeMetricCounter("wss_relay_bytes_to_upstream_total", "Total bytes client to Telegram", float64(snapshot.BytesToUpstream))
	writeMetricCounter("wss_relay_bytes_from_upstream_total", "Total bytes Telegram to client", float64(snapshot.BytesFromUpstream))
	writeMetricCounter("wss_relay_mux_tunnels_total", "Total mux tunnels opened", float64(snapshot.MuxTunnelsTotal))
	writeMetricCounter("wss_relay_mux_streams_opened_total", "Total mux streams opened", float64(snapshot.MuxStreamsOpened))
	writeMetricCounter("wss_relay_mux_streams_closed_total", "Total mux streams closed", float64(snapshot.MuxStreamsClosed))
	writeMetricCounter("wss_relay_upstream_dial_errors_total", "Upstream TCP dial errors", float64(snapshot.UpstreamDialErrors))
	writeMetricCounter("wss_relay_upstream_blocked_total", "Upstream blocked by allowlist", float64(snapshot.UpstreamBlocked))
	writeMetricCounter("wss_relay_tunnel_limit_rejected_total", "Mux tunnel limit rejections (429)", float64(snapshot.TunnelLimitRejected))
	writeMetricCounter("wss_relay_auth_failures_total", "Auth failures (401)", float64(snapshot.AuthFailures))
	writeMetricCounter("wss_relay_ws_upgrade_failures_total", "WebSocket upgrade failures", float64(snapshot.WSUpgradeFailures))
	writeMetricCounter("wss_relay_mux_open_fail_dial_total", "Mux open failures (dial)", float64(snapshot.MuxOpenFailDial))
	writeMetricCounter("wss_relay_mux_open_limit_total", "Mux open failures (stream limit)", float64(snapshot.MuxOpenLimit))
	writeMetricCounter("wss_relay_mux_open_bad_total", "Mux open failures (bad request)", float64(snapshot.MuxOpenBad))
	writeMetricGauge("wss_relay_mux_open_dial_ms_avg", "Average upstream dial latency ms", float64(snapshot.MuxOpenDialMsAvg))
	writeMetricGauge("wss_relay_mux_open_dial_ms_p95", "p95 upstream dial latency ms", float64(snapshot.MuxOpenDialMsP95))
	for _, client := range snapshot.Clients {
		labels := fmt.Sprintf(`{ip=%q}`, client.IP)
		b.WriteString("wss_relay_client_active_tunnels")
		b.WriteString(labels)
		b.WriteString(" ")
		b.WriteString(strconv.Itoa(client.ActiveTunnels))
		b.WriteString("\n")
		b.WriteString("wss_relay_client_active_streams")
		b.WriteString(labels)
		b.WriteString(" ")
		b.WriteString(strconv.Itoa(client.ActiveStreams))
		b.WriteString("\n")
		b.WriteString("wss_relay_client_bytes_to_upstream_per_sec")
		b.WriteString(labels)
		b.WriteString(" ")
		b.WriteString(formatPromFloat(client.Rates.BytesToUpstreamPerSec))
		b.WriteString("\n")
		b.WriteString("wss_relay_client_bytes_from_upstream_per_sec")
		b.WriteString(labels)
		b.WriteString(" ")
		b.WriteString(formatPromFloat(client.Rates.BytesFromUpstreamPerSec))
		b.WriteString("\n")
	}
	for _, entry := range snapshot.Abuse {
		labels := fmt.Sprintf(`{ip=%q}`, entry.IP)
		b.WriteString("wss_relay_abuse_auth_failures_total")
		b.WriteString(labels)
		b.WriteString(" ")
		b.WriteString(strconv.FormatInt(entry.AuthFailures, 10))
		b.WriteString("\n")
		b.WriteString("wss_relay_abuse_tunnel_limit_total")
		b.WriteString(labels)
		b.WriteString(" ")
		b.WriteString(strconv.FormatInt(entry.TunnelLimitRejected, 10))
		b.WriteString("\n")
		b.WriteString("wss_relay_abuse_upstream_blocked_total")
		b.WriteString(labels)
		b.WriteString(" ")
		b.WriteString(strconv.FormatInt(entry.UpstreamBlocked, 10))
		b.WriteString("\n")
	}
	_, _ = w.Write([]byte(b.String()))
}

func formatPromFloat(value float64) string {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "0"
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func handleMetricsHTTP(w http.ResponseWriter, r *http.Request) {
	handleMetrics(w, relayStatistics.snapshot())
}
