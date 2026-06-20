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
	maxStreams := flag.Int("max-streams", 256, "Max mux streams per tunnel")
	maxTunnelsPerIP := flag.Int("max-tunnels-per-ip", 12, "Max mux WebSocket tunnels per client IP (0 = unlimited)")
	streamIdleTimeout := flag.Duration("stream-idle-timeout", 10*time.Minute, "Close mux streams with no traffic for this long (0 = disabled)")
	wsPingInterval := flag.Duration("ws-ping-interval", 30*time.Second, "WebSocket ping interval per tunnel (0 = disabled)")
	wsReadTimeout := flag.Duration("ws-read-timeout", 90*time.Second, "WebSocket read deadline, extended on traffic/pong (0 = disabled)")
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

	muxLimiter := newMuxTunnelLimiter(*maxTunnelsPerIP)
	muxConfig := muxConfig{
		maxStreams:        *maxStreams,
		streamIdleTimeout: *streamIdleTimeout,
		wsPingInterval:    *wsPingInterval,
		wsReadTimeout:     *wsReadTimeout,
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
		"wss-relay listening on %s mux-path=%s stats=%s auth=%s max-streams=%d max-tunnels-per-ip=%d stream-idle=%s ws-ping=%s ws-read=%s telegram-only=%v",
		*listen,
		*muxPath,
		statsInfo,
		authInfo,
		*maxStreams,
		*maxTunnelsPerIP,
		*streamIdleTimeout,
		*wsPingInterval,
		*wsReadTimeout,
		*telegramOnly,
	)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
