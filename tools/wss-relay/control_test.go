package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStatsRestartAllowedWithAuth(t *testing.T) {
	auth, err := loadTokenAuth("", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/stats/restart", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	if !statsRestartAllowed(req, auth) {
		t.Fatal("expected restart allowed with valid token")
	}
	req.Header.Set("Authorization", "Bearer wrong")
	if statsRestartAllowed(req, auth) {
		t.Fatal("expected restart denied with wrong token")
	}
}

func TestStatsRestartAllowedLocalhost(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/stats/restart", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	if !statsRestartAllowed(req, nil) {
		t.Fatal("expected restart allowed from localhost without auth")
	}
	req.RemoteAddr = "203.0.113.1:12345"
	if statsRestartAllowed(req, nil) {
		t.Fatal("expected restart denied from remote without auth")
	}
}

func TestHandleStatsRestartMethod(t *testing.T) {
	auth, err := loadTokenAuth("", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/stats/restart", nil)
	rec := httptest.NewRecorder()
	handleStatsRestart(rec, req, auth)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
}
