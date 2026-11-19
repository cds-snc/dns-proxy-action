package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Records are sent in batches so a DNS answer never waits on Sentinel.
	sentinelBatchSize     = 100
	sentinelFlushInterval = time.Second
	sentinelQueueSize     = 10000

	// Refresh the Azure access token this long before it expires.
	sentinelTokenRefreshMargin = 5 * time.Minute

	// A batch that fails with a retryable error is sent up to this many
	// times, waiting sentinelRetryBackoff (doubled each time) in between.
	sentinelMaxAttempts  = 3
	sentinelRetryBackoff = time.Second
)

// permanentError marks a send failure that retrying will not fix.
type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

// statusError returns an error for a non-2xx response. Only 401 (handled by
// requesting a new token), 408, 429 and 5xx are worth retrying.
func statusError(prefix string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	err := fmt.Errorf("%s failed with status %d: %s", prefix, resp.StatusCode, strings.TrimSpace(string(body)))
	switch {
	case resp.StatusCode == http.StatusUnauthorized,
		resp.StatusCode == http.StatusRequestTimeout,
		resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode >= 500:
		return err
	}
	return permanentError{err}
}

type SentinelForwarder struct {
	config *Config
	client *http.Client
	queue  chan []byte
	flush  chan chan struct{}

	retryBackoff time.Duration

	// ctx is cancelled when the shutdown deadline passes, which aborts any
	// request or retry wait still in progress.
	ctx    context.Context
	cancel context.CancelFunc

	// closed stops Write from queueing records once shutdown has started.
	mu     sync.RWMutex
	closed bool

	// pending counts records that were queued but not yet sent or dropped.
	pending atomic.Int64
	// rejected counts records that arrived after shutdown started.
	rejected atomic.Int64

	// Only used by the worker goroutine.
	accessToken          string
	accessTokenRefreshAt time.Time
}

func NewSentinelForwarder(config *Config) *SentinelForwarder {
	return newSentinelForwarder(config, newUpstreamHTTPClient(config))
}

func newSentinelForwarder(config *Config, client *http.Client) *SentinelForwarder {
	ctx, cancel := context.WithCancel(context.Background())
	w := &SentinelForwarder{
		config: config,
		client: client,
		queue:  make(chan []byte, sentinelQueueSize),
		flush:  make(chan chan struct{}),
		ctx:    ctx,
		cancel: cancel,

		retryBackoff: sentinelRetryBackoff,
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

func getGitHubOIDCToken(ctx context.Context, client *http.Client, audience string) (string, error) {
	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if requestURL == "" || requestToken == "" {
		return "", permanentError{fmt.Errorf("missing GitHub OIDC environment variables")}
	}

	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		return "", err
	}
	query := parsedURL.Query()
	query.Set("audience", audience)
	parsedURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
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
		return "", statusError("GitHub OIDC token request", resp)
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
func getAzureMonitorAccessToken(ctx context.Context, client *http.Client, config *Config) (string, time.Duration, error) {
	oidcToken, err := getGitHubOIDCToken(ctx, client, config.SentinelOIDCAudience)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
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
		return "", 0, statusError("Azure token request", resp)
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
func (w *SentinelForwarder) cachedAccessToken(ctx context.Context) (string, error) {
	if w.accessToken != "" && time.Now().Before(w.accessTokenRefreshAt) {
		return w.accessToken, nil
	}

	token, expiresIn, err := getAzureMonitorAccessToken(ctx, w.client, w.config)
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

// sendLegacy and sendOIDC return nil on success, a permanentError when
// retrying cannot help, and any other error when the batch should be retried.
func (w *SentinelForwarder) sendLegacy(ctx context.Context, lines [][]byte) error {
	if w.config.LogAnalyticsWorkspaceId == "" || w.config.LogAnalyticsSharedKey == "" || w.config.LogAnalyticsTable == "" {
		return permanentError{fmt.Errorf("Sentinel forwarding is enabled (legacy mode), but required Log Analytics settings are missing")}
	}

	q, err := buildSentinelPayload(lines)
	if err != nil {
		return permanentError{fmt.Errorf("Error preparing legacy Sentinel payload: %w", err)}
	}

	rfc1123Date := time.Now().UTC().Format(time.RFC1123)
	rfc1123Date = rfc1123Date[:len(rfc1123Date)-3] + "GMT"
	signature, err := buildSignature(w.config.LogAnalyticsWorkspaceId, w.config.LogAnalyticsSharedKey, rfc1123Date, fmt.Sprint(len(q)), http.MethodPost, "application/json", "/api/logs")
	if err != nil {
		return permanentError{fmt.Errorf("Error building legacy signature: %w", err)}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, buildLegacyIngestionURI(w.config), bytes.NewReader(q))
	if err != nil {
		return permanentError{fmt.Errorf("Error creating legacy request: %w", err)}
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("Authorization", signature)
	req.Header.Set("Log-Type", w.config.LogAnalyticsTable)
	req.Header.Set("x-ms-date", rfc1123Date)

	response, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("Error sending legacy request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		err := statusError("Legacy ingestion request", response)
		if response.StatusCode == http.StatusUnauthorized {
			// The shared key does not change between attempts.
			return permanentError{err}
		}
		return err
	}
	return nil
}

func (w *SentinelForwarder) sendOIDC(ctx context.Context, lines [][]byte) error {
	if w.config.SentinelTenantID == "" || w.config.SentinelClientID == "" || w.config.SentinelDCEURI == "" || w.config.SentinelDCRImmutableID == "" || w.config.SentinelStreamName == "" {
		return permanentError{fmt.Errorf("Sentinel forwarding is enabled (oidc mode), but required OIDC/DCR settings are missing")}
	}

	q, err := buildSentinelPayload(lines)
	if err != nil {
		return permanentError{fmt.Errorf("Error preparing Sentinel payload: %w", err)}
	}

	accessToken, err := w.cachedAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("Error getting Azure access token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, buildIngestionURI(w.config), bytes.NewReader(q))
	if err != nil {
		return permanentError{fmt.Errorf("Error creating request: %w", err)}
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	response, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("Error sending request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		if response.StatusCode == http.StatusUnauthorized {
			// Request a new token for the next attempt.
			w.accessToken = ""
		}
		return statusError("Ingestion request", response)
	}
	return nil
}

// send sends one batch, retrying retryable failures with backoff. A batch
// that still fails is dropped and logged, so a broken destination cannot
// make the queue grow without limit.
func (w *SentinelForwarder) send(lines [][]byte) {
	if len(lines) == 0 {
		return
	}
	defer w.pending.Add(-int64(len(lines)))

	backoff := w.retryBackoff
	for attempt := 1; ; attempt++ {
		var err error
		if useLegacySentinelForwarding(w.config) {
			err = w.sendLegacy(w.ctx, lines)
		} else {
			err = w.sendOIDC(w.ctx, lines)
		}
		if err == nil {
			return
		}
		fmt.Printf("Error sending %d Sentinel records (attempt %d of %d): %v\n", len(lines), attempt, sentinelMaxAttempts, err)

		var permanent permanentError
		if errors.As(err, &permanent) || attempt >= sentinelMaxAttempts || w.ctx.Err() != nil {
			fmt.Printf("Dropping %d Sentinel records that could not be sent\n", len(lines))
			return
		}

		select {
		case <-time.After(backoff):
		case <-w.ctx.Done():
			fmt.Printf("Dropping %d Sentinel records that could not be sent\n", len(lines))
			return
		}
		backoff *= 2
	}
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

// flushQueue asks the worker to send every queued record and reports whether
// it finished before deadline.
func (w *SentinelForwarder) flushQueue(deadline <-chan time.Time) bool {
	done := make(chan struct{})
	select {
	case w.flush <- done:
	case <-deadline:
		return false
	}
	select {
	case <-done:
		return true
	case <-deadline:
		return false
	}
}

// Shutdown stops accepting records and sends the ones already queued. It
// returns within timeout: when the deadline passes, requests in progress are
// cancelled and the number of records that were not sent is logged.
func (w *SentinelForwarder) Shutdown(timeout time.Duration) {
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	defer w.cancel()

	if !w.flushQueue(deadline.C) {
		w.cancel()
		fmt.Printf("Sentinel shutdown timed out after %s, %d queued records were not sent\n", timeout, w.pending.Load())
	}
	if n := w.rejected.Load(); n > 0 {
		fmt.Printf("%d Sentinel records arrived after shutdown started and were not sent\n", n)
	}
}

// Write queues the record for the worker and returns straight away, so the
// DNS answer is not held up by requests to Sentinel.
func (w *SentinelForwarder) Write(p []byte) (n int, err error) {
	if !w.config.ForwardToSentinel || !bytes.Contains(p, []byte("\"domain\":")) {
		return len(p), nil
	}

	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		w.rejected.Add(1)
		return len(p), nil
	}

	// zerolog reuses p once Write returns, so queue a copy.
	w.pending.Add(1)
	select {
	case w.queue <- bytes.Clone(p):
	default:
		w.pending.Add(-1)
		fmt.Println("Sentinel forwarding queue is full, dropping record")
	}
	return len(p), nil
}
