package main

import (
	"net"
	"testing"
)

func TestTelegramAllowlistKnownDc(t *testing.T) {
	allowlist, err := newTelegramUpstreamAllowlist(true)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := allowlist.allowsHost("149.154.167.91")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("expected telegram dc ip to be allowed")
	}
}

func TestTelegramAllowlistBlocksPublicResolver(t *testing.T) {
	allowlist, err := newTelegramUpstreamAllowlist(true)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := allowlist.allowsHost("8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("expected 8.8.8.8 to be blocked")
	}
}

func TestTelegramAllowlistDisabled(t *testing.T) {
	allowlist, err := newTelegramUpstreamAllowlist(false)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := allowlist.allowsHost("8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("expected allowlist disabled to permit any host")
	}
}

func TestTelegramAllowlistEmbeddedNetworks(t *testing.T) {
	allowlist, err := newTelegramUpstreamAllowlist(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowlist.nets) < 10 {
		t.Fatalf("expected embedded cidr list, got %d networks", len(allowlist.nets))
	}
	ip := net.ParseIP("91.108.4.1")
	if !allowlist.contains(ip) {
		t.Fatal("expected 91.108.4.1 to match embedded range")
	}
}
