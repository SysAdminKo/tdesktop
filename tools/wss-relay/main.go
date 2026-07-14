package main

import (
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func tuneTCP(conn net.Conn) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.SetNoDelay(true)
	_ = tcp.SetReadBuffer(512 * 1024)
	_ = tcp.SetWriteBuffer(512 * 1024)
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8283", "HTTP listen address")
	muxPath := flag.String("mux-path", "/ws/mux", "WebSocket mux path")
	maxStreams := flag.Int("max-streams", 64, "Max mux streams per tunnel")
	maxTunnelsPerIP := flag.Int("max-tunnels-per-ip", 12, "Max mux WebSocket tunnels per client IP (0 = unlimited)")
	streamIdleTimeout := flag.Duration("stream-idle-timeout", 10*time.Minute, "Close mux streams with no traffic for this long (0 = disabled)")
	upstreamPoolMin := flag.Int("upstream-pool-min", 2, "Minimum warm upstream connections per egress/target bucket (0 = disable pool)")
	upstreamPoolMax := flag.Int("upstream-pool-max", 15, "Maximum warm upstream connections per egress/target bucket")
	upstreamPoolIdle := flag.Duration("upstream-pool-idle", 60*time.Second, "Max age of a warm pooled upstream connection before it is dropped")
	upstreamPoolTargetHit := flag.Int("upstream-pool-target-hit", 40, "Target pool hit percent; grow bucket size when below this")
	upstreamPoolAdjustInterval := flag.Duration("upstream-pool-adjust-interval", 5*time.Second, "Adaptive pool resize interval per bucket")
	upstreamPoolBucketRetention := flag.Duration("upstream-pool-bucket-retention", 10*time.Minute, "Drop a bucket after this long without client traffic to its egress/target pair")
	upstreamPoolGlobalMaxIdle := flag.Int("upstream-pool-global-max-idle", 500, "Max total idle upstream connections across all buckets")
	egressBindIPs := flag.String("egress-bind-ips", "", "Comma-separated local IPs allowed for upstream bind (empty = any from X-Relay-Local-IP)")
	wsPingInterval := flag.Duration("ws-ping-interval", 30*time.Second, "WebSocket ping interval per tunnel (0 = disabled)")
	wsReadTimeout := flag.Duration("ws-read-timeout", 90*time.Second, "WebSocket read deadline, extended on traffic/pong (0 = disabled)")
	upstreamStallRotate := flag.Int("upstream-stall-rotate", muxUpstreamMaxConsecutiveReadStallsDef, "Close mux stream after this many consecutive upstream read stalls (0 = log only)")
	telegramOnly := flag.Bool("telegram-only", true, "Allow upstream TCP only to Telegram DC CIDRs")
	statsPath := flag.String("stats-path", "/stats", "Live stats UI path (empty to disable)")
	authFile := flag.String("auth-file", "", "Path to file with sha256 token hashes (one per line)")
	authToken := flag.String("auth-token", "", "Single access token (dev only; prefer -auth-file)")
	flag.Parse()

	tokenAuth, err := loadTokenAuth(*authFile, *authToken)
	if err != nil {
		log.Fatal(err)
	}

	allowlist, err := newTelegramUpstreamAllowlist(*telegramOnly)
	if err != nil {
		log.Fatal(err)
	}
	telegramAllowlist = allowlist

	setAllowedEgressIPs(*egressBindIPs)
	initUpstreamPool(upstreamPoolConfig{
		minSize:          *upstreamPoolMin,
		maxSize:          *upstreamPoolMax,
		maxIdle:          *upstreamPoolIdle,
		bucketRetention:  *upstreamPoolBucketRetention,
		targetHitPct:     *upstreamPoolTargetHit,
		adjustInterval:   *upstreamPoolAdjustInterval,
		globalMaxIdle:    *upstreamPoolGlobalMaxIdle,
	})

	relayStatistics.setConfig(statsConfigSnapshot{
		MaxStreams:           *maxStreams,
		MaxTunnelsPerIP:      *maxTunnelsPerIP,
		StreamIdleTimeoutSec: streamIdleTimeout.Seconds(),
		WSPingIntervalSec:    wsPingInterval.Seconds(),
		WSReadTimeoutSec:     wsReadTimeout.Seconds(),
		TelegramOnly:         *telegramOnly,
		AuthEnabled:          tokenAuth != nil,
	})

	muxLimiter := newMuxTunnelLimiter(*maxTunnelsPerIP)
	muxConfig := muxConfig{
		maxStreams:               *maxStreams,
		streamIdleTimeout:        *streamIdleTimeout,
		wsPingInterval:           *wsPingInterval,
		wsReadTimeout:            *wsReadTimeout,
		maxConsecutiveReadStalls: *upstreamStallRotate,
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if statsPathEnabled(*statsPath) {
			base := strings.TrimSuffix(*statsPath, "/")
			if r.URL.Path == base || r.URL.Path == base+"/" {
				handleStatsPage(w, r)
				return
			}
			if r.URL.Path == base+"/json" {
				handleStatsJSON(w, r)
				return
			}
			if r.URL.Path == base+"/metrics" {
				handleMetricsHTTP(w, r)
				return
			}
			if r.URL.Path == base+"/restart" {
				handleStatsRestart(w, r, tokenAuth)
				return
			}
		}
		if *muxPath != "" && (r.URL.Path == *muxPath || strings.HasPrefix(r.URL.Path, *muxPath+"/")) {
			handleMux(w, r, muxConfig, muxLimiter, tokenAuth)
			return
		}
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "OK")
			return
		}
		http.NotFound(w, r)
	})

	statsInfo := "disabled"
	if statsPathEnabled(*statsPath) {
		statsInfo = *statsPath
	}
	authInfo := "disabled"
	if tokenAuth != nil {
		authInfo = "enabled"
	}
	log.Printf(
		"wss-relay listening on %s mux-path=%s stats=%s auth=%s max-streams=%d max-tunnels-per-ip=%d stream-idle=%s ws-ping=%s ws-read=%s upstream-stall-rotate=%d telegram-only=%v upstream-pool=%d..%d idle=%s target-hit=%d%% adjust=%s global-idle=%d egress-bind=%q",
		*listen,
		*muxPath,
		statsInfo,
		authInfo,
		*maxStreams,
		*maxTunnelsPerIP,
		*streamIdleTimeout,
		*wsPingInterval,
		*wsReadTimeout,
		*upstreamStallRotate,
		*telegramOnly,
		*upstreamPoolMin,
		*upstreamPoolMax,
		*upstreamPoolIdle,
		*upstreamPoolTargetHit,
		*upstreamPoolAdjustInterval,
		*upstreamPoolGlobalMaxIdle,
		*egressBindIPs,
	)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
