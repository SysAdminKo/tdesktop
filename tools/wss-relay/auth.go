package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type tokenAuth struct {
	hashes [][]byte
}

func loadTokenAuth(authFile, authToken string) (*tokenAuth, error) {
	if authFile == "" && authToken == "" {
		return nil, nil
	}
	result := &tokenAuth{}
	if authToken != "" {
		result.hashes = append(result.hashes, hashToken(authToken))
	}
	if authFile != "" {
		data, err := os.ReadFile(authFile)
		if err != nil {
			return nil, fmt.Errorf("read auth file: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			hash, err := parseTokenHashLine(line)
			if err != nil {
				return nil, fmt.Errorf("auth file: %w", err)
			}
			result.hashes = append(result.hashes, hash)
		}
	}
	if len(result.hashes) == 0 {
		return nil, fmt.Errorf("no auth tokens configured")
	}
	return result, nil
}

func parseTokenHashLine(line string) ([]byte, error) {
	value := strings.TrimSpace(strings.TrimPrefix(line, "sha256:"))
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("bad sha256 hash %q", line)
	}
	if len(decoded) != sha256.Size {
		return nil, fmt.Errorf("bad sha256 length for %q", line)
	}
	return decoded, nil
}

func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func parseBearerToken(r *http.Request) (token string, ok bool) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return "", false
	}
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return "", false
	}
	token = strings.TrimSpace(auth[7:])
	return token, token != ""
}

func (a *tokenAuth) validate(r *http.Request) (label string, ok bool) {
	if a == nil {
		return "", true
	}
	token, ok := parseBearerToken(r)
	if !ok {
		return "", false
	}
	digest := hashToken(token)
	for _, expected := range a.hashes {
		if subtle.ConstantTimeCompare(digest, expected) == 1 {
			return "token", true
		}
	}
	return "", false
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="wss-relay", charset="UTF-8"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
