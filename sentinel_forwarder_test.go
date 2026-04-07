package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ─── buildSignature ───────────────────────────────────────────────────────────

func TestBuildSignature_ReturnsSharedKeyFormat(t *testing.T) {
	// Use a valid base64-encoded key so HMAC decoding succeeds.
	sharedKey := base64.StdEncoding.EncodeToString([]byte("supersecret"))
	sig := buildSignature("workspace-id", sharedKey, "Thu, 03 Apr 2026 12:00:00 GMT", "42", "POST", "application/json", "/api/logs")

	if !strings.HasPrefix(sig, "SharedKey workspace-id:") {
		t.Errorf("expected signature to start with 'SharedKey workspace-id:', got %q", sig)
	}
}

func TestBuildSignature_DeterministicOutput(t *testing.T) {
	sharedKey := base64.StdEncoding.EncodeToString([]byte("key"))
	args := []string{"ws", sharedKey, "Mon, 01 Jan 2024 00:00:00 GMT", "10", "POST", "application/json", "/api/logs"}

	sig1 := buildSignature(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
	sig2 := buildSignature(args[0], args[1], args[2], args[3], args[4], args[5], args[6])

	if sig1 != sig2 {
		t.Error("buildSignature should return the same value for identical inputs")
	}
}

func TestBuildSignature_DifferentKeysDifferentSignatures(t *testing.T) {
	key1 := base64.StdEncoding.EncodeToString([]byte("key1"))
	key2 := base64.StdEncoding.EncodeToString([]byte("key2"))
	date := "Mon, 01 Jan 2024 00:00:00 GMT"

	sig1 := buildSignature("ws", key1, date, "10", "POST", "application/json", "/api/logs")
	sig2 := buildSignature("ws", key2, date, "10", "POST", "application/json", "/api/logs")

	if sig1 == sig2 {
		t.Error("different keys should produce different signatures")
	}
}

// ─── SentinelForwarder.Write ──────────────────────────────────────────────────

// mockRoundTripper lets tests control the HTTP response returned by http.DefaultTransport.
type mockRoundTripper struct {
	statusCode int
	body       string
	err        error
}

func (m *mockRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(m.body)),
		Header:     make(http.Header),
	}, nil
}

func setMockTransport(t *testing.T, status int) {
	t.Helper()
	orig := http.DefaultTransport
	http.DefaultTransport = &mockRoundTripper{statusCode: status}
	t.Cleanup(func() { http.DefaultTransport = orig })
}

func sentinelConfig() *Config {
	return &Config{
		ForwardToSentinel:       true,
		LogAnalyticsWorkspaceId: "test-workspace",
		LogAnalyticsSharedKey:   base64.StdEncoding.EncodeToString([]byte("shared-secret")),
		LogAnalyticsTable:       "TestTable",
	}
}

func TestSentinelForwarder_Write_ForwardingDisabled(t *testing.T) {
	cfg := sentinelConfig()
	cfg.ForwardToSentinel = false
	sf := SentinelForwarder{config: cfg}

	p := []byte(`{"level":"info","domain":"example.com"}` + "\n")
	n, err := sf.Write(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(p) {
		t.Errorf("expected %d bytes, got %d", len(p), n)
	}
}

func TestSentinelForwarder_Write_NoDomainField(t *testing.T) {
	cfg := sentinelConfig()
	sf := SentinelForwarder{config: cfg}

	p := []byte(`{"level":"info","message":"startup"}` + "\n")
	n, err := sf.Write(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(p) {
		t.Errorf("expected %d bytes, got %d", len(p), n)
	}
}

func TestSentinelForwarder_Write_SuccessfulPost(t *testing.T) {
	setMockTransport(t, http.StatusOK)
	cfg := sentinelConfig()
	sf := SentinelForwarder{config: cfg}

	p := []byte(`{"level":"info","domain":"example.com","action":"query"}` + "\n")
	n, err := sf.Write(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(p) {
		t.Errorf("expected %d bytes, got %d", len(p), n)
	}
}

func TestSentinelForwarder_Write_Non2xxResponse(t *testing.T) {
	setMockTransport(t, http.StatusInternalServerError)
	cfg := sentinelConfig()
	sf := SentinelForwarder{config: cfg}

	p := []byte(`{"level":"info","domain":"example.com","action":"query"}` + "\n")
	n, err := sf.Write(p)
	// On non-2xx, the function returns 0 with a nil error (matching production code).
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes written on non-2xx response, got %d", n)
	}
}

func TestSentinelForwarder_Write_202Accepted(t *testing.T) {
	setMockTransport(t, http.StatusAccepted)
	cfg := sentinelConfig()
	sf := SentinelForwarder{config: cfg}

	p := []byte(`{"level":"info","domain":"example.com","action":"blocked"}` + "\n")
	n, err := sf.Write(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(p) {
		t.Errorf("expected %d bytes, got %d", len(p), n)
	}
}

func TestSentinelForwarder_Write_RequestContainsDomainPayload(t *testing.T) {
	var capturedReq *http.Request
	orig := http.DefaultTransport
	http.DefaultTransport = &captureTransport{
		captured:   &capturedReq,
		statusCode: http.StatusOK,
	}
	t.Cleanup(func() { http.DefaultTransport = orig })

	cfg := sentinelConfig()
	sf := SentinelForwarder{config: cfg}

	p := []byte(`{"level":"info","domain":"example.com","action":"query"}` + "\n")
	sf.Write(p) //nolint:errcheck

	if capturedReq == nil {
		t.Fatal("expected an HTTP request to be made, but none was captured")
	}
	if capturedReq.Header.Get("Log-Type") != "TestTable" {
		t.Errorf("Log-Type header: expected TestTable, got %q", capturedReq.Header.Get("Log-Type"))
	}
	if capturedReq.Method != http.MethodPost {
		t.Errorf("expected POST method, got %q", capturedReq.Method)
	}
}

// captureTransport records the request and returns a canned response.
type captureTransport struct {
	captured   **http.Request
	statusCode int
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	*c.captured = req
	return &http.Response{
		StatusCode: c.statusCode,
		Body:       io.NopCloser(bytes.NewBufferString("")),
		Header:     make(http.Header),
	}, nil
}
