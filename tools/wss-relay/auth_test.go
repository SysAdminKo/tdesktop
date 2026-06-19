package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTokenAuthBearer(t *testing.T) {
	auth, err := loadTokenAuth("", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/ws/mux", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	if label, ok := auth.validate(req); !ok || label != "token" {
		t.Fatalf("expected bearer token ok, got label=%q ok=%v", label, ok)
	}
}

func TestTokenAuthDisabled(t *testing.T) {
	var auth *tokenAuth
	req := httptest.NewRequest(http.MethodGet, "/ws/mux", nil)
	if label, ok := auth.validate(req); !ok || label != "" {
		t.Fatalf("expected open access, got label=%q ok=%v", label, ok)
	}
}

func TestTokenAuthReject(t *testing.T) {
	auth, err := loadTokenAuth("", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/ws/mux", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	if _, ok := auth.validate(req); ok {
		t.Fatal("expected reject")
	}
}
