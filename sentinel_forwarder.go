package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

type SentinelForwarder struct {
	config *Config
}

func buildSignature(customerID, sharedKey, date, contentLength, method, contentType, resource string) string {
	xHeaders := "x-ms-date:" + date
	stringToHash := method + "\n" + contentLength + "\n" + contentType + "\n" + xHeaders + "\n" + resource
	bytesToHash := []byte(stringToHash)
	decodedKey, _ := base64.StdEncoding.DecodeString(sharedKey)
	hash := hmac.New(sha256.New, decodedKey)
	hash.Write(bytesToHash)
	encodedHash := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	authorization := fmt.Sprintf("SharedKey %s:%s", customerID, encodedHash)
	return authorization
}

func (w SentinelForwarder) Write(p []byte) (n int, err error) {
	if w.config.ForwardToSentinel && bytes.Contains(p, []byte("\"domain\":")) {
		method := "POST"
		contentType := "application/json"
		resource := "/api/logs"
		rfc1123Date := time.Now().UTC().Format(time.RFC1123)
		rfc1123Date = rfc1123Date[:len(rfc1123Date)-3] + "GMT"
		contentLength := fmt.Sprint(len(p))
		signature := buildSignature(w.config.LogAnalyticsWorkspaceId, w.config.LogAnalyticsSharedKey, rfc1123Date, contentLength, method, contentType, resource)
		uri := fmt.Sprintf("https://%s.ods.opinsights.azure.com%s?api-version=2016-04-01", w.config.LogAnalyticsWorkspaceId, resource)

		client := &http.Client{Timeout: 10 * time.Second}

		req, err := http.NewRequest("POST", uri, bytes.NewReader(p))
		if err != nil {
			fmt.Println("Error creating request:", err)
			return 0, err
		}

		req.Header.Set("content-type", contentType)
		req.Header.Set("Authorization", signature)
		req.Header.Set("Log-Type", w.config.LogAnalyticsTable)
		req.Header.Set("x-ms-date", rfc1123Date)

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
