package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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

func buildOIDCSentinelPayload(p []byte) ([]byte, error) {
	var evt map[string]any
	if err := json.Unmarshal(p, &evt); err != nil {
		return nil, err
	}

	enrichWithGitHubContext(evt)

	// DCR ingestion expects an array of JSON records.
	records := []map[string]any{evt}
	return json.Marshal(records)
}

func buildLegacySentinelPayload(p []byte) ([]byte, error) {
	var evt map[string]any
	if err := json.Unmarshal(p, &evt); err != nil {
		return nil, err
	}

	enrichWithGitHubContext(evt)
	return json.Marshal(evt)
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

func buildLegacyIngestionURI(config *Config) string {
	return fmt.Sprintf("https://%s.ods.opinsights.azure.com/api/logs?api-version=2016-04-01", config.LogAnalyticsWorkspaceId)
}

func (w SentinelForwarder) writeLegacy(p []byte) (n int, err error) {
	if w.config.LogAnalyticsWorkspaceId == "" || w.config.LogAnalyticsSharedKey == "" || w.config.LogAnalyticsTable == "" {
		fmt.Println("Sentinel forwarding is enabled (legacy mode), but required Log Analytics settings are missing")
		return len(p), nil
	}

	q, err := buildLegacySentinelPayload(p)
	if err != nil {
		fmt.Println("Error preparing legacy Sentinel payload:", err)
		return 0, err
	}

	rfc1123Date := time.Now().UTC().Format(time.RFC1123)
	rfc1123Date = rfc1123Date[:len(rfc1123Date)-3] + "GMT"
	signature, err := buildSignature(w.config.LogAnalyticsWorkspaceId, w.config.LogAnalyticsSharedKey, rfc1123Date, fmt.Sprint(len(q)), http.MethodPost, "application/json", "/api/logs")
	if err != nil {
		fmt.Println("Error building legacy signature:", err)
		return 0, err
	}

	req, err := http.NewRequest(http.MethodPost, buildLegacyIngestionURI(w.config), bytes.NewReader(q))
	if err != nil {
		fmt.Println("Error creating legacy request:", err)
		return 0, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("Authorization", signature)
	req.Header.Set("Log-Type", w.config.LogAnalyticsTable)
	req.Header.Set("x-ms-date", rfc1123Date)

	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending legacy request:", err)
		return 0, err
	}
	defer response.Body.Close()

	if response.StatusCode >= 200 && response.StatusCode <= 299 {
		return len(p), nil
	}

	fmt.Println("Legacy response code:", response.StatusCode)
	return 0, nil
}

func (w SentinelForwarder) writeOIDC(p []byte) (n int, err error) {
	if w.config.SentinelTenantID == "" || w.config.SentinelClientID == "" || w.config.SentinelDCEURI == "" || w.config.SentinelDCRImmutableID == "" || w.config.SentinelStreamName == "" {
		fmt.Println("Sentinel forwarding is enabled (oidc mode), but required OIDC/DCR settings are missing")
		return len(p), nil
	}

	q, err := buildOIDCSentinelPayload(p)
	if err != nil {
		fmt.Println("Error preparing Sentinel payload:", err)
		return 0, err
	}

	accessToken, err := getAzureMonitorAccessToken(w.config)
	if err != nil {
		fmt.Println("Error getting Azure access token:", err)
		return 0, err
	}

	req, err := http.NewRequest(http.MethodPost, buildIngestionURI(w.config), bytes.NewReader(q))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return 0, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return 0, err
	}
	defer response.Body.Close()

	if response.StatusCode >= 200 && response.StatusCode <= 299 {
		return len(p), nil
	}

	fmt.Println("Response code:", response.StatusCode)
	return 0, nil
}

func (w SentinelForwarder) Write(p []byte) (n int, err error) {
	if !w.config.ForwardToSentinel || !bytes.Contains(p, []byte("\"domain\":")) {
		return len(p), nil
	}

	if useLegacySentinelForwarding(w.config) {
		return w.writeLegacy(p)
	}

	return w.writeOIDC(p)
}
