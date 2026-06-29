package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type SentinelForwarder struct {
	config *Config
}

func normalizeDomainName(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func extractDomainFromLogEvent(p []byte) (string, bool) {
	var evt map[string]any
	if err := json.Unmarshal(p, &evt); err != nil {
		return "", false
	}

	raw, ok := evt["domain"]
	if !ok {
		return "", false
	}

	domain, ok := raw.(string)
	if !ok {
		return "", false
	}

	return normalizeDomainName(domain), domain != ""
}

func shouldSkipSentinelForwarding(domain string, config *Config) bool {
	domain = normalizeDomainName(domain)
	if domain == "" {
		return false
	}

	// Avoid recursive DNS dependencies when obtaining OIDC and Azure tokens.
	if domain == "token.actions.githubusercontent.com" || domain == "login.microsoftonline.com" {
		return true
	}
	if strings.HasSuffix(domain, ".actions.githubusercontent.com") {
		return true
	}

	// DCE host should never re-enter forwarding path.
	dceHost := sentinelIngestionHost(config.SentinelDCEURI)
	if dceHost != "" && domain == dceHost {
		return true
	}

	return false
}

func buildSentinelPayload(p []byte) ([]byte, error) {
	var evt map[string]any
	if err := json.Unmarshal(p, &evt); err != nil {
		return nil, err
	}

	evt["actor"] = os.Getenv("GITHUB_ACTOR")
	evt["eventName"] = os.Getenv("GITHUB_EVENT_NAME")
	evt["job"] = os.Getenv("GITHUB_JOB")
	evt["repository"] = os.Getenv("GITHUB_REPOSITORY")
	evt["runNumber"] = os.Getenv("GITHUB_RUN_NUMBER")
	evt["sha"] = os.Getenv("GITHUB_SHA")
	evt["workflow"] = os.Getenv("GITHUB_WORKFLOW")
	evt["workflow_ref"] = os.Getenv("GITHUB_REF")

	// DCR ingestion expects an array of JSON records.
	records := []map[string]any{evt}
	return json.Marshal(records)
}

func getGitHubOIDCToken(audience string) (string, error) {
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

	client := &http.Client{Timeout: 10 * time.Second}
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

func getAzureMonitorAccessToken(config *Config) (string, error) {
	oidcToken, err := getGitHubOIDCToken(config.SentinelOIDCAudience)
	if err != nil {
		return "", err
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
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Azure token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", err
	}
	if tokenResponse.AccessToken == "" {
		return "", fmt.Errorf("Azure token response did not include access_token")
	}

	return tokenResponse.AccessToken, nil
}

func buildIngestionURI(config *Config) string {
	return strings.TrimRight(config.SentinelDCEURI, "/") + "/dataCollectionRules/" + config.SentinelDCRImmutableID + "/streams/" + config.SentinelStreamName + "?api-version=2023-01-01"
}

func (w SentinelForwarder) Write(p []byte) (n int, err error) {
	if w.config.ForwardToSentinel && bytes.Contains(p, []byte("\"domain\":")) {
		if domain, ok := extractDomainFromLogEvent(p); ok && shouldSkipSentinelForwarding(domain, w.config) {
			return len(p), nil
		}

		if w.config.SentinelTenantID == "" || w.config.SentinelClientID == "" || w.config.SentinelDCEURI == "" || w.config.SentinelDCRImmutableID == "" || w.config.SentinelStreamName == "" {
			fmt.Println("Sentinel forwarding is enabled, but required OIDC/DCR settings are missing")
			return len(p), nil
		}

		q, err := buildSentinelPayload(p)
		if err != nil {
			fmt.Println("Error preparing Sentinel payload:", err)
			return 0, err
		}

		accessToken, err := getAzureMonitorAccessToken(w.config)
		if err != nil {
			fmt.Println("Error getting Azure access token:", err)
			return 0, err
		}

		uri := buildIngestionURI(w.config)

		client := &http.Client{Timeout: 10 * time.Second}

		req, err := http.NewRequest("POST", uri, bytes.NewReader(q))
		if err != nil {
			fmt.Println("Error creating request:", err)
			return 0, err
		}

		req.Header.Set("content-type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessToken)

		response, err := client.Do(req)
		if err != nil {
			fmt.Println("Error sending request:", err)
			return 0, err
		}
		defer response.Body.Close()

		if response.StatusCode >= 200 && response.StatusCode <= 299 {
			return len(p), err
		} else {
			fmt.Println("Response code:", response.StatusCode)
			return 0, err
		}
	}
	return len(p), nil
}
