package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

type statsControlSnapshot struct {
	RestartEnabled bool `json:"restart_enabled"`
	AuthRequired   bool `json:"auth_required"`
}

func statsRestartAllowed(r *http.Request, auth *tokenAuth) bool {
	if auth != nil {
		_, ok := auth.validate(r)
		return ok
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	return host == "127.0.0.1" || host == "::1"
}

func scheduleProcessRestart() {
	go func() {
		time.Sleep(400 * time.Millisecond)
		log.Println("stats: restart requested, exiting for systemd")
		os.Exit(0)
	}()
}

func handleStatsRestart(w http.ResponseWriter, r *http.Request, auth *tokenAuth) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !statsRestartAllowed(r, auth) {
		if auth != nil {
			writeUnauthorized(w)
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "restarting",
	})
	scheduleProcessRestart()
}
