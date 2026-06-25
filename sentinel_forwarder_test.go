package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

type oidcDCRTransport struct {
	t                    *testing.T
	capturedIngestHeader http.Header
	capturedIngestBody   []byte
	ingestCalls          int
}

func (m *oidcDCRTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.t.Helper()

	switch {
	case strings.Contains(req.URL.Host, "token.actions.githubusercontent.com"):
		if req.Method != http.MethodGet {
			m.t.Fatalf("expected GET for GitHub OIDC token request, got %s", req.Method)
		}
		if req.Header.Get("Authorization") != "bearer test-gh-request-token" {
			m.t.Fatalf("unexpected GitHub token authorization header: %q", req.Header.Get("Authorization"))
		}
		if req.URL.Query().Get("audience") != "api://AzureADTokenExchange" {
			m.t.Fatalf("unexpected OIDC audience: %q", req.URL.Query().Get("audience"))
		}
		return jsonResponse(http.StatusOK, `{"value":"github-oidc-token"}`), nil

	case strings.Contains(req.URL.Host, "login.microsoftonline.com"):
		if req.Method != http.MethodPost {
			m.t.Fatalf("expected POST for Azure token request, got %s", req.Method)
		}
		body, _ := io.ReadAll(req.Body)
		values, err := url.ParseQuery(string(body))
		if err != nil {
			m.t.Fatalf("unable to parse Azure token form body: %v", err)
		}
		if values.Get("client_assertion") != "github-oidc-token" {
			m.t.Fatalf("expected client_assertion to carry GitHub OIDC token")
		}
		if values.Get("scope") != "https://monitor.azure.com/.default" {
			m.t.Fatalf("unexpected scope: %q", values.Get("scope"))
		}
		if values.Get("client_id") != "client-id" {
			m.t.Fatalf("unexpected client_id: %q", values.Get("client_id"))
		}
		return jsonResponse(http.StatusOK, `{"access_token":"azure-access-token"}`), nil

	case strings.Contains(req.URL.Host, "example-dce.eastus-1.ingest.monitor.azure.com"):
		m.ingestCalls++
		m.capturedIngestHeader = req.Header.Clone()
		m.capturedIngestBody, _ = io.ReadAll(req.Body)
		if req.Method != http.MethodPost {
			m.t.Fatalf("expected POST for DCR ingestion request, got %s", req.Method)
		}
		if !strings.Contains(req.URL.Path, "/dataCollectionRules/dcr-immutable-id/streams/Custom-GitHubMetadata_CI_DNS_Queries_V2_CL") {
			m.t.Fatalf("unexpected ingestion path: %s", req.URL.Path)
		}
		return jsonResponse(http.StatusAccepted, `{}`), nil
	}

	m.t.Fatalf("unexpected request to host: %s", req.URL.Host)
	return nil, nil
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}

func sentinelConfig() *Config {
	return &Config{
		ForwardToSentinel:      true,
		SentinelTenantID:       "tenant-id",
		SentinelClientID:       "client-id",
		SentinelOIDCAudience:   "api://AzureADTokenExchange",
		SentinelDCEURI:         "https://example-dce.eastus-1.ingest.monitor.azure.com",
		SentinelDCRImmutableID: "dcr-immutable-id",
		SentinelStreamName:     "Custom-GitHubMetadata_CI_DNS_Queries_V2_CL",
	}
}

func TestBuildSentinelPayload_AddsGitHubContextAndWrapsArray(t *testing.T) {
	t.Setenv("GITHUB_ACTOR", "octocat")
	t.Setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
	t.Setenv("GITHUB_JOB", "audit")
	t.Setenv("GITHUB_REPOSITORY", "org/repo")
	t.Setenv("GITHUB_RUN_NUMBER", "42")
	t.Setenv("GITHUB_SHA", "abc123")
	t.Setenv("GITHUB_WORKFLOW", "dns-audit")
	t.Setenv("GITHUB_REF", "refs/heads/main")

	payload, err := buildSentinelPayload([]byte(`{"domain":"example.com","action":"query"}`))
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

	_, err := getGitHubOIDCToken("api://AzureADTokenExchange")
	if err == nil {
		t.Fatal("expected error when OIDC environment variables are missing")
	}
}

func TestSentinelForwarder_Write_OIDCToDCRSuccess(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.actions.githubusercontent.com/.well-known/openid-configuration?id=abc")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-gh-request-token")
	t.Setenv("GITHUB_ACTOR", "octocat")
	t.Setenv("GITHUB_EVENT_NAME", "push")
	t.Setenv("GITHUB_JOB", "dns")
	t.Setenv("GITHUB_REPOSITORY", "org/repo")
	t.Setenv("GITHUB_RUN_NUMBER", "77")
	t.Setenv("GITHUB_SHA", "deadbeef")
	t.Setenv("GITHUB_WORKFLOW", "ci")
	t.Setenv("GITHUB_REF", "refs/heads/main")

	transport := &oidcDCRTransport{t: t}
	orig := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = orig })

	sf := SentinelForwarder{config: sentinelConfig()}
	p := []byte(`{"level":"info","domain":"example.com","action":"query"}` + "\n")

	n, err := sf.Write(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(p) {
		t.Fatalf("expected %d bytes written, got %d", len(p), n)
	}
	if transport.ingestCalls != 1 {
		t.Fatalf("expected one ingestion call, got %d", transport.ingestCalls)
	}
	if transport.capturedIngestHeader.Get("Authorization") != "Bearer azure-access-token" {
		t.Fatalf("unexpected ingestion authorization header: %q", transport.capturedIngestHeader.Get("Authorization"))
	}

	var records []map[string]any
	if err := json.Unmarshal(transport.capturedIngestBody, &records); err != nil {
		t.Fatalf("expected ingestion body to be JSON array: %v", err)
	}
	if len(records) != 1 || records[0]["domain"] != "example.com" {
		t.Fatalf("unexpected ingestion body: %s", string(transport.capturedIngestBody))
	}
}

func TestSentinelForwarder_Write_MissingOIDCConfigNoop(t *testing.T) {
	cfg := sentinelConfig()
	cfg.SentinelClientID = ""
	sf := SentinelForwarder{config: cfg}

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
	cfg := sentinelConfig()
	cfg.ForwardToSentinel = false
	sf := SentinelForwarder{config: cfg}

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
	sf := SentinelForwarder{config: sentinelConfig()}
	p := []byte(`{"level":"info","message":"startup"}` + "\n")

	n, err := sf.Write(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(p) {
		t.Fatalf("expected %d bytes written, got %d", len(p), n)
	}
}
