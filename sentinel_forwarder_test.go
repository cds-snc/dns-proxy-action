package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

type dualModeTransport struct {
	t *testing.T

	azureTokenCalls   int
	oidcIngestCalls   int
	legacyIngestCalls int

	capturedOIDCHeader   http.Header
	capturedOIDCBody     []byte
	capturedLegacyHeader http.Header
	capturedLegacyBody   []byte
}

func (m *dualModeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.t.Helper()

	switch {
	case strings.Contains(req.URL.Host, "token.actions.githubusercontent.com"):
		if req.Method != http.MethodGet {
			m.t.Errorf("expected GET for GitHub OIDC token request, got %s", req.Method)
		}
		if req.Header.Get("Authorization") != "bearer test-gh-request-token" {
			m.t.Errorf("unexpected GitHub token authorization header: %q", req.Header.Get("Authorization"))
		}
		if req.URL.Query().Get("audience") != "api://AzureADTokenExchange" {
			m.t.Errorf("unexpected OIDC audience: %q", req.URL.Query().Get("audience"))
		}
		return jsonResponse(http.StatusOK, `{"value":"github-oidc-token"}`), nil

	case strings.Contains(req.URL.Host, "login.microsoftonline.com"):
		if req.Method != http.MethodPost {
			m.t.Errorf("expected POST for Azure token request, got %s", req.Method)
		}
		body, _ := io.ReadAll(req.Body)
		values, err := url.ParseQuery(string(body))
		if err != nil {
			m.t.Errorf("unable to parse Azure token form body: %v", err)
		}
		if values.Get("client_assertion") != "github-oidc-token" {
			m.t.Errorf("expected client_assertion to carry GitHub OIDC token")
		}
		if values.Get("scope") != "https://monitor.azure.com/.default" {
			m.t.Errorf("unexpected scope: %q", values.Get("scope"))
		}
		if values.Get("client_id") != "client-id" {
			m.t.Errorf("unexpected client_id: %q", values.Get("client_id"))
		}
		m.azureTokenCalls++
		return jsonResponse(http.StatusOK, `{"access_token":"azure-access-token","expires_in":3599}`), nil

	case strings.Contains(req.URL.Host, "example-dce.eastus-1.ingest.monitor.azure.com"):
		m.oidcIngestCalls++
		m.capturedOIDCHeader = req.Header.Clone()
		m.capturedOIDCBody, _ = io.ReadAll(req.Body)
		if req.Method != http.MethodPost {
			m.t.Errorf("expected POST for DCR ingestion request, got %s", req.Method)
		}
		if !strings.Contains(req.URL.Path, "/dataCollectionRules/dcr-immutable-id/streams/Custom-GitHubMetadata_CI_DNS_Queries_V2_Input") {
			m.t.Errorf("unexpected ingestion path: %s", req.URL.Path)
		}
		return jsonResponse(http.StatusAccepted, `{}`), nil

	case strings.Contains(req.URL.Host, ".ods.opinsights.azure.com"):
		m.legacyIngestCalls++
		m.capturedLegacyHeader = req.Header.Clone()
		m.capturedLegacyBody, _ = io.ReadAll(req.Body)
		if req.Method != http.MethodPost {
			m.t.Errorf("expected POST for legacy ingestion request, got %s", req.Method)
		}
		if req.URL.Path != "/api/logs" {
			m.t.Errorf("unexpected legacy ingestion path: %s", req.URL.Path)
		}
		return jsonResponse(http.StatusOK, `{}`), nil
	}

	m.t.Errorf("unexpected request to host: %s", req.URL.Host)
	return jsonResponse(http.StatusNotFound, `{}`), nil
}

// newTestForwarder returns a forwarder that sends its requests through transport.
func newTestForwarder(cfg *Config, transport http.RoundTripper) *SentinelForwarder {
	return newSentinelForwarder(cfg, &http.Client{Transport: transport})
}

func setOIDCEnv(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.actions.githubusercontent.com/.well-known/openid-configuration?id=abc")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-gh-request-token")
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}

func oidcConfig() *Config {
	return &Config{
		ForwardToSentinel:      true,
		SentinelForwardingMode: SentinelForwardingModeOIDC,
		SentinelTenantID:       "tenant-id",
		SentinelClientID:       "client-id",
		SentinelOIDCAudience:   "api://AzureADTokenExchange",
		SentinelDCEURI:         "https://example-dce.eastus-1.ingest.monitor.azure.com",
		SentinelDCRImmutableID: "dcr-immutable-id",
		SentinelStreamName:     "Custom-GitHubMetadata_CI_DNS_Queries_V2_Input",
	}
}

func legacyConfig() *Config {
	return &Config{
		ForwardToSentinel:       true,
		SentinelForwardingMode:  SentinelForwardingModeLegacy,
		LogAnalyticsWorkspaceId: "legacy-workspace",
		LogAnalyticsSharedKey:   base64.StdEncoding.EncodeToString([]byte("legacy-secret")),
		LogAnalyticsTable:       "LegacyTable",
	}
}

func TestBuildSentinelPayload_AddsGitHubContextAndWrapsArray(t *testing.T) {
	t.Setenv("GITHUB_ACTOR", "octocat")
	t.Setenv("GITHUB_EVENT_NAME", "workflow_dispatch")

	payload, err := buildSentinelPayload([][]byte{[]byte(`{"domain":"example.com","action":"query"}`)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var records []map[string]any
	if err := json.Unmarshal(payload, &records); err != nil {
		t.Fatalf("payload should be valid JSON array: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected exactly one record, got %d", len(records))
	}
	if records[0]["domain"] != "example.com" {
		t.Fatalf("expected original domain field to be preserved")
	}
	if records[0]["actor"] != "octocat" {
		t.Fatalf("expected GitHub actor context to be included")
	}
}

func TestGetGitHubOIDCToken_MissingEnvironment(t *testing.T) {
	_ = os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	_ = os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

	_, err := getGitHubOIDCToken(http.DefaultClient, "api://AzureADTokenExchange")
	if err == nil {
		t.Fatal("expected error when OIDC environment variables are missing")
	}
}

func TestSentinelForwarder_Write_OIDCToDCRSuccess(t *testing.T) {
	setOIDCEnv(t)
	t.Setenv("GITHUB_ACTOR", "octocat")
	t.Setenv("GITHUB_EVENT_NAME", "push")
	t.Setenv("GITHUB_JOB", "dns")
	t.Setenv("GITHUB_REPOSITORY", "org/repo")
	t.Setenv("GITHUB_RUN_NUMBER", "77")
	t.Setenv("GITHUB_SHA", "deadbeef")
	t.Setenv("GITHUB_WORKFLOW", "ci")
	t.Setenv("GITHUB_REF", "refs/heads/main")

	transport := &dualModeTransport{t: t}
	sf := newTestForwarder(oidcConfig(), transport)
	p := []byte(`{"level":"info","domain":"example.com","action":"query"}` + "\n")

	n, err := sf.Write(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(p) {
		t.Fatalf("expected %d bytes written, got %d", len(p), n)
	}
	sf.Flush(5 * time.Second)
	if transport.oidcIngestCalls != 1 {
		t.Fatalf("expected one OIDC ingestion call, got %d", transport.oidcIngestCalls)
	}
	if transport.legacyIngestCalls != 0 {
		t.Fatalf("expected zero legacy ingestion calls, got %d", transport.legacyIngestCalls)
	}
	if transport.capturedOIDCHeader.Get("Authorization") != "Bearer azure-access-token" {
		t.Fatalf("unexpected OIDC authorization header: %q", transport.capturedOIDCHeader.Get("Authorization"))
	}
}

func TestSentinelForwarder_Write_LegacySuccess(t *testing.T) {
	t.Setenv("GITHUB_ACTOR", "octocat")

	transport := &dualModeTransport{t: t}
	sf := newTestForwarder(legacyConfig(), transport)
	p := []byte(`{"level":"info","domain":"example.com","action":"query"}` + "\n")

	n, err := sf.Write(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(p) {
		t.Fatalf("expected %d bytes written, got %d", len(p), n)
	}
	sf.Flush(5 * time.Second)
	if transport.legacyIngestCalls != 1 {
		t.Fatalf("expected one legacy ingestion call, got %d", transport.legacyIngestCalls)
	}
	if transport.capturedLegacyHeader.Get("Log-Type") != "LegacyTable" {
		t.Fatalf("unexpected Log-Type header: %q", transport.capturedLegacyHeader.Get("Log-Type"))
	}
	if !strings.HasPrefix(transport.capturedLegacyHeader.Get("Authorization"), "SharedKey legacy-workspace:") {
		t.Fatalf("unexpected legacy Authorization header: %q", transport.capturedLegacyHeader.Get("Authorization"))
	}
}

func TestSentinelForwarder_Write_AutoModeUsesLegacyWhenLegacyCredsPresent(t *testing.T) {
	cfg := legacyConfig()
	cfg.SentinelForwardingMode = SentinelForwardingModeAuto

	transport := &dualModeTransport{t: t}
	sf := newTestForwarder(cfg, transport)
	p := []byte(`{"level":"info","domain":"example.com","action":"query"}` + "\n")

	n, err := sf.Write(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(p) {
		t.Fatalf("expected %d bytes written, got %d", len(p), n)
	}
	sf.Flush(5 * time.Second)
	if transport.legacyIngestCalls != 1 {
		t.Fatalf("expected one legacy ingestion call in auto mode, got %d", transport.legacyIngestCalls)
	}
}

func TestSentinelForwarder_Write_MissingConfigNoop(t *testing.T) {
	cfg := oidcConfig()
	cfg.SentinelClientID = ""
	sf := newTestForwarder(cfg, &dualModeTransport{t: t})

	p := []byte(`{"level":"info","domain":"example.com","action":"query"}` + "\n")
	n, err := sf.Write(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(p) {
		t.Fatalf("expected %d bytes written, got %d", len(p), n)
	}
}

func TestSentinelForwarder_Write_ForwardingDisabled(t *testing.T) {
	cfg := oidcConfig()
	cfg.ForwardToSentinel = false
	sf := newTestForwarder(cfg, &dualModeTransport{t: t})

	p := []byte(`{"level":"info","domain":"example.com"}` + "\n")
	n, err := sf.Write(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(p) {
		t.Fatalf("expected %d bytes written, got %d", len(p), n)
	}
}

func TestSentinelForwarder_Write_NoDomainField(t *testing.T) {
	sf := newTestForwarder(oidcConfig(), &dualModeTransport{t: t})
	p := []byte(`{"level":"info","message":"startup"}` + "\n")

	n, err := sf.Write(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(p) {
		t.Fatalf("expected %d bytes written, got %d", len(p), n)
	}
}

func TestSentinelForwarder_Write_BatchesRecords(t *testing.T) {
	setOIDCEnv(t)

	transport := &dualModeTransport{t: t}
	sf := newTestForwarder(oidcConfig(), transport)
	for _, domain := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		sf.Write([]byte(`{"level":"info","domain":"` + domain + `","action":"query"}` + "\n"))
	}
	sf.Flush(5 * time.Second)

	if transport.oidcIngestCalls != 1 {
		t.Fatalf("expected one OIDC ingestion call for the batch, got %d", transport.oidcIngestCalls)
	}
	var records []map[string]any
	if err := json.Unmarshal(transport.capturedOIDCBody, &records); err != nil {
		t.Fatalf("payload should be valid JSON array: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 records in the batch, got %d", len(records))
	}
}

func TestSentinelForwarder_Write_SplitsLargeBatches(t *testing.T) {
	setOIDCEnv(t)

	transport := &dualModeTransport{t: t}
	sf := newTestForwarder(oidcConfig(), transport)
	for range sentinelBatchSize + 1 {
		sf.Write([]byte(`{"level":"info","domain":"example.com","action":"query"}` + "\n"))
	}
	sf.Flush(5 * time.Second)

	if transport.oidcIngestCalls != 2 {
		t.Fatalf("expected two OIDC ingestion calls, got %d", transport.oidcIngestCalls)
	}
}

func TestSentinelForwarder_Write_CachesAccessToken(t *testing.T) {
	setOIDCEnv(t)

	transport := &dualModeTransport{t: t}
	sf := newTestForwarder(oidcConfig(), transport)
	for range 2 {
		sf.Write([]byte(`{"level":"info","domain":"example.com","action":"query"}` + "\n"))
		sf.Flush(5 * time.Second)
	}

	if transport.oidcIngestCalls != 2 {
		t.Fatalf("expected two OIDC ingestion calls, got %d", transport.oidcIngestCalls)
	}
	if transport.azureTokenCalls != 1 {
		t.Fatalf("expected the Azure access token to be requested once, got %d", transport.azureTokenCalls)
	}
}

type blockingTransport struct {
	release chan struct{}
}

func (b *blockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	<-b.release
	return jsonResponse(http.StatusOK, `{}`), nil
}

func TestSentinelForwarder_Write_DoesNotWaitForSentinel(t *testing.T) {
	transport := &blockingTransport{release: make(chan struct{})}
	t.Cleanup(func() { close(transport.release) })
	sf := newTestForwarder(legacyConfig(), transport)

	done := make(chan struct{})
	go func() {
		for range sentinelBatchSize * 2 {
			sf.Write([]byte(`{"level":"info","domain":"example.com","action":"query"}` + "\n"))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Write blocked while a Sentinel request was in progress")
	}
}

func TestSentinelForwarder_Write_CopiesRecord(t *testing.T) {
	transport := &dualModeTransport{t: t}
	sf := newTestForwarder(legacyConfig(), transport)

	p := []byte(`{"level":"info","domain":"example.com","action":"query"}` + "\n")
	sf.Write(p)
	// zerolog reuses its buffer after Write returns.
	copy(p, bytes.Repeat([]byte("x"), len(p)))
	sf.Flush(5 * time.Second)

	var records []map[string]any
	if err := json.Unmarshal(transport.capturedLegacyBody, &records); err != nil {
		t.Fatalf("payload should be valid JSON array: %v", err)
	}
	if len(records) != 1 || records[0]["domain"] != "example.com" {
		t.Fatalf("expected the original record to be sent, got %v", records)
	}
}
