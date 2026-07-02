package main

import "testing"

func TestDcLabelForTarget(t *testing.T) {
	cases := map[string]string{
		"149.154.167.91:443":  "DC2/4 Amsterdam",
		"149.154.167.255:443": "DC2/4 Amsterdam",
		"149.154.175.50:443":  "DC1/3 Miami",
		"149.154.171.5:443":   "DC5 Singapore",
		"91.108.56.130:443":   "DC5 Singapore",
		"8.8.8.8:443":         "",
		"not-an-ip:443":       "",
		"149.154.167.91":      "DC2/4 Amsterdam",
		"91.108.8.5:443":      "Telegram",
		"185.76.151.10:443":   "Telegram",
		"[2001:b28:f23d:f001::a]:443": "DC1/3 Miami",
		"[2001:67c:4e8:f002::a]:443":  "DC2/4 Amsterdam",
		"[2001:b28:f23f:f005::a]:443": "DC5 Singapore",
		"[2a0a:f280::1]:443":          "Telegram",
	}
	for target, want := range cases {
		if got := dcLabelForTarget(target); got != want {
			t.Errorf("dcLabelForTarget(%q) = %q, want %q", target, got, want)
		}
	}
}
