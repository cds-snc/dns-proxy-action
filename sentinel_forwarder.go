package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// Records are sent in batches so a DNS answer never waits on Sentinel.
	sentinelBatchSize     = 100
	sentinelFlushInterval = time.Second
	sentinelQueueSize     = 10000

	// Refresh the Azure access token this long before it expires.
	sentinelTokenRefreshMargin = 5 * time.Minute
)

type SentinelForwarder struct {
	config *Config
	client *http.Client
	queue  chan []byte
	flush  chan chan struct{}

	// Only used by the worker goroutine.
	accessToken          string
	accessTokenRefreshAt time.Time
}

func NewSentinelForwarder(config *Config) *SentinelForwarder {
	return newSentinelForwarder(config, newUpstreamHTTPClient(config))
}

func newSentinelForwarder(config *Config, client *http.Client) *SentinelForwarder {
	w := &SentinelForwarder{
		config: config,
		client: client,
		queue:  make(chan []byte, sentinelQueueSize),
		flush:  make(chan chan struct{}),
	}
	go w.run()
	return w
}

// newUpstreamHTTPClient returns a client that resolves hostnames with the
// upstream DNS server directly. The system resolver points at this proxy, so
// using it would log the forwarder's own lookups and send those to Sentinel
// as well, which in turn triggers more lookups.
func newUpstreamHTTPClient(config *Config) *http.Client {
	upstreamAddr := fmt.Sprintf("%s:53", config.UpstreamServer)
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, upstreamAddr)
			},
		},
	}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         dialer.DialContext,
		ForceAttemptHTTP2:   true,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: transport}
}

func enrichWithGitHubContext(evt map[string]any) {
	evt["actor"] = os.Getenv("GITHUB_ACTOR")
	evt["eventName"] = os.Getenv("GITHUB_EVENT_NAME")
	evt["job"] = os.Getenv("GITHUB_JOB")
	evt["repository"] = os.Getenv("GITHUB_REPOSITORY")
	evt["runNumber"] = os.Getenv("GITHUB_RUN_NUMBER")
	evt["sha"] = os.Getenv("GITHUB_SHA")
	evt["workflow"] = os.Getenv("GITHUB_WORKFLOW")
	evt["workflow_ref"] = os.Getenv("GITHUB_REF")
}

// buildSentinelPayload returns the records as a JSON array, which both the
// DCR ingestion API and the legacy Data Collector API accept. Records that
// are not valid JSON are skipped.
func buildSentinelPayload(lines [][]byte) ([]byte, error) {
	records := []map[string]any{}
	for _, p := range lines {
		var evt map[string]any
		if err := json.Unmarshal(p, &evt); err != nil {
			fmt.Println("Error decoding Sentinel record:", err)
			continue
		}
		enrichWithGitHubContext(evt)
		records = append(records, evt)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no valid records to send")
	}
	return json.Marshal(records)
}

func buildSignature(customerID, sharedKey, date, contentLength, method, contentType, resource string) (string, error) {
	xHeaders := "x-ms-date:" + date
	stringToHash := method + "\n" + contentLength + "\n" + contentType + "\n" + xHeaders + "\n" + resource
	decodedKey, err := base64.StdEncoding.DecodeString(sharedKey)
	if err != nil {
		return "", err
	}
	hash := hmac.New(sha256.New, decodedKey)
	hash.Write([]byte(stringToHash))
	encodedHash := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	return fmt.Sprintf("SharedKey %s:%s", customerID, encodedHash), nil
}

func getGitHubOIDCToken(client *http.Client, audience string) (string, error) {
	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if requestURL == "" || requestToken == "" {
		return "", fmt.Errorf("missing GitHub OIDC environment variables")
	}

	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		return "", err
	}
	query := parsedURL.Query()
	query.Set("audience", audience)
	parsedURL.RawQuery = query.Encode()

	req, err := http.NewRequest(http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "bearer "+requestToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GitHub OIDC token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", err
	}
	if tokenResponse.Value == "" {
		return "", fmt.Errorf("GitHub OIDC token response did not include a token")
	}

	return tokenResponse.Value, nil
}

// getAzureMonitorAccessToken returns an access token and how long it is valid for.
func getAzureMonitorAccessToken(client *http.Client, config *Config) (string, time.Duration, error) {
	oidcToken, err := getGitHubOIDCToken(client, config.SentinelOIDCAudience)
	if err != nil {
		return "", 0, err
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", config.SentinelClientID)
	form.Set("scope", "https://monitor.azure.com/.default")
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", oidcToken)

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", config.SentinelTenantID)
	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(resp.Body)
		return "", 0, fmt.Errorf("Azure token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", 0, err
	}
	if tokenResponse.AccessToken == "" {
		return "", 0, fmt.Errorf("Azure token response did not include access_token")
	}

	return tokenResponse.AccessToken, time.Duration(tokenResponse.ExpiresIn) * time.Second, nil
}

// cachedAccessToken returns the cached Azure access token, requesting a new
// one when there is none or it is about to expire.
func (w *SentinelForwarder) cachedAccessToken() (string, error) {
	if w.accessToken != "" && time.Now().Before(w.accessTokenRefreshAt) {
		return w.accessToken, nil
	}

	token, expiresIn, err := getAzureMonitorAccessToken(w.client, w.config)
	if err != nil {
		return "", err
	}
	w.accessToken = token
	w.accessTokenRefreshAt = time.Now().Add(expiresIn - sentinelTokenRefreshMargin)
	return token, nil
}

func buildIngestionURI(config *Config) string {
	return strings.TrimRight(config.SentinelDCEURI, "/") + "/dataCollectionRules/" + config.SentinelDCRImmutableID + "/streams/" + config.SentinelStreamName + "?api-version=2023-01-01"
}

func buildLegacyIngestionURI(config *Config) string {
	return fmt.Sprintf("https://%s.ods.opinsights.azure.com/api/logs?api-version=2016-04-01", config.LogAnalyticsWorkspaceId)
}

func (w *SentinelForwarder) sendLegacy(lines [][]byte) error {
	if w.config.LogAnalyticsWorkspaceId == "" || w.config.LogAnalyticsSharedKey == "" || w.config.LogAnalyticsTable == "" {
		fmt.Println("Sentinel forwarding is enabled (legacy mode), but required Log Analytics settings are missing")
		return nil
	}

	q, err := buildSentinelPayload(lines)
	if err != nil {
		fmt.Println("Error preparing legacy Sentinel payload:", err)
		return err
	}

	rfc1123Date := time.Now().UTC().Format(time.RFC1123)
	rfc1123Date = rfc1123Date[:len(rfc1123Date)-3] + "GMT"
	signature, err := buildSignature(w.config.LogAnalyticsWorkspaceId, w.config.LogAnalyticsSharedKey, rfc1123Date, fmt.Sprint(len(q)), http.MethodPost, "application/json", "/api/logs")
	if err != nil {
		fmt.Println("Error building legacy signature:", err)
		return err
	}

	req, err := http.NewRequest(http.MethodPost, buildLegacyIngestionURI(w.config), bytes.NewReader(q))
	if err != nil {
		fmt.Println("Error creating legacy request:", err)
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("Authorization", signature)
	req.Header.Set("Log-Type", w.config.LogAnalyticsTable)
	req.Header.Set("x-ms-date", rfc1123Date)

	response, err := w.client.Do(req)
	if err != nil {
		fmt.Println("Error sending legacy request:", err)
		return err
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		fmt.Println("Legacy response code:", response.StatusCode)
	}
	return nil
}

func (w *SentinelForwarder) sendOIDC(lines [][]byte) error {
	if w.config.SentinelTenantID == "" || w.config.SentinelClientID == "" || w.config.SentinelDCEURI == "" || w.config.SentinelDCRImmutableID == "" || w.config.SentinelStreamName == "" {
		fmt.Println("Sentinel forwarding is enabled (oidc mode), but required OIDC/DCR settings are missing")
		return nil
	}

	q, err := buildSentinelPayload(lines)
	if err != nil {
		fmt.Println("Error preparing Sentinel payload:", err)
		return err
	}

	accessToken, err := w.cachedAccessToken()
	if err != nil {
		fmt.Println("Error getting Azure access token:", err)
		return err
	}

	req, err := http.NewRequest(http.MethodPost, buildIngestionURI(w.config), bytes.NewReader(q))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	response, err := w.client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusUnauthorized {
		// Request a new token for the next batch.
		w.accessToken = ""
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		fmt.Println("Response code:", response.StatusCode)
	}
	return nil
}

func (w *SentinelForwarder) send(lines [][]byte) {
	if len(lines) == 0 {
		return
	}
	if useLegacySentinelForwarding(w.config) {
		w.sendLegacy(lines)
		return
	}
	w.sendOIDC(lines)
}

// sendInBatches sends the records sentinelBatchSize at a time.
func (w *SentinelForwarder) sendInBatches(lines [][]byte) {
	for len(lines) > 0 {
		n := min(len(lines), sentinelBatchSize)
		w.send(lines[:n])
		lines = lines[n:]
	}
}

func (w *SentinelForwarder) run() {
	ticker := time.NewTicker(sentinelFlushInterval)
	defer ticker.Stop()

	var batch [][]byte
	for {
		select {
		case record := <-w.queue:
			batch = append(batch, record)
			if len(batch) >= sentinelBatchSize {
				w.send(batch)
				batch = nil
			}
		case <-ticker.C:
			w.send(batch)
			batch = nil
		case done := <-w.flush:
			for drained := false; !drained; {
				select {
				case record := <-w.queue:
					batch = append(batch, record)
				default:
					drained = true
				}
			}
			w.sendInBatches(batch)
			batch = nil
			close(done)
		}
	}
}

// Flush sends every queued record, waiting at most timeout for it to finish.
func (w *SentinelForwarder) Flush(timeout time.Duration) {
	done := make(chan struct{})
	select {
	case w.flush <- done:
	case <-time.After(timeout):
		return
	}
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// Write queues the record for the worker and returns straight away, so the
// DNS answer is not held up by requests to Sentinel.
func (w *SentinelForwarder) Write(p []byte) (n int, err error) {
	if !w.config.ForwardToSentinel || !bytes.Contains(p, []byte("\"domain\":")) {
		return len(p), nil
	}

	// zerolog reuses p once Write returns, so queue a copy.
	select {
	case w.queue <- bytes.Clone(p):
	default:
		fmt.Println("Sentinel forwarding queue is full, dropping record")
	}
	return len(p), nil
}
