package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func newQueryLoggerConfig(t *testing.T) *Config {
	t.Helper()
	tmp := t.TempDir()
	return &Config{
		QueryLogFilePath: tmp + "/dns_query.log",
		Logger:           zerolog.New(io.Discard),
	}
}

func TestQueryLogger_Write_WithDomain(t *testing.T) {
	cfg := newQueryLoggerConfig(t)
	ql := QueryLogger{config: cfg}

	event := []byte(`{"level":"info","domain":"example.com","action":"query"}` + "\n")
	n, err := ql.Write(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(event) {
		t.Errorf("Write returned %d bytes, expected %d", n, len(event))
	}

	contents, err := os.ReadFile(cfg.QueryLogFilePath)
	if err != nil {
		t.Fatalf("could not read log file: %v", err)
	}
	if !strings.Contains(string(contents), "example.com") {
		t.Errorf("log file does not contain expected domain; got: %s", string(contents))
	}
}

func TestQueryLogger_Write_WithoutDomain(t *testing.T) {
	cfg := newQueryLoggerConfig(t)
	ql := QueryLogger{config: cfg}

	event := []byte(`{"level":"info","message":"no domain field here"}` + "\n")
	n, err := ql.Write(event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(event) {
		t.Errorf("Write returned %d bytes, expected %d", n, len(event))
	}

	// File should not have been created because there is no "domain" field.
	if _, statErr := os.Stat(cfg.QueryLogFilePath); !os.IsNotExist(statErr) {
		t.Error("log file should not be written when event has no domain field")
	}
}

func TestQueryLogger_Write_InvalidJSON(t *testing.T) {
	cfg := newQueryLoggerConfig(t)
	ql := QueryLogger{config: cfg}

	_, err := ql.Write([]byte(`not valid json`))
	if err == nil {
		t.Error("expected error for invalid JSON input")
	}
}

func TestQueryLogger_Write_MultipleEvents(t *testing.T) {
	cfg := newQueryLoggerConfig(t)
	ql := QueryLogger{config: cfg}

	event1 := []byte(`{"level":"info","domain":"first.com","action":"query"}` + "\n")
	event2 := []byte(`{"level":"info","domain":"second.com","action":"query"}` + "\n")

	if _, err := ql.Write(event1); err != nil {
		t.Fatalf("error writing event1: %v", err)
	}
	if _, err := ql.Write(event2); err != nil {
		t.Fatalf("error writing event2: %v", err)
	}

	contents, err := os.ReadFile(cfg.QueryLogFilePath)
	if err != nil {
		t.Fatalf("could not read log file: %v", err)
	}
	if !strings.Contains(string(contents), "first.com") || !strings.Contains(string(contents), "second.com") {
		t.Errorf("log file missing expected domains; got: %s", string(contents))
	}
}

func TestQueryLogger_Write_MixedEvents(t *testing.T) {
	cfg := newQueryLoggerConfig(t)
	ql := QueryLogger{config: cfg}

	withDomain := []byte(`{"level":"info","domain":"recorded.com","action":"query"}` + "\n")
	withoutDomain := []byte(`{"level":"info","message":"startup"}` + "\n")

	if _, err := ql.Write(withDomain); err != nil {
		t.Fatalf("error writing domain event: %v", err)
	}
	if _, err := ql.Write(withoutDomain); err != nil {
		t.Fatalf("error writing non-domain event: %v", err)
	}

	contents, err := os.ReadFile(cfg.QueryLogFilePath)
	if err != nil {
		t.Fatalf("could not read log file: %v", err)
	}
	if strings.Contains(string(contents), "startup") {
		t.Error("log file should not contain non-domain events")
	}
	if !strings.Contains(string(contents), "recorded.com") {
		t.Error("log file should contain domain event")
	}
}
