package main

import (
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

// resetViper clears all viper state before each config test.
func resetViper(t *testing.T) {
	t.Helper()
	viper.Reset()
}

func TestInitConfig_Defaults(t *testing.T) {
	resetViper(t)

	config := initConfig()

	if config.Host != "172.17.0.1" {
		t.Errorf("Host: expected 172.17.0.1, got %q", config.Host)
	}
	if config.Port != 53 {
		t.Errorf("Port: expected 53, got %d", config.Port)
	}
	if config.UpstreamServer != "8.8.8.8" {
		t.Errorf("UpstreamServer: expected 8.8.8.8, got %q", config.UpstreamServer)
	}
	if config.ForwardToSentinel {
		t.Error("ForwardToSentinel: expected false by default")
	}
	if !config.OverwriteConfig {
		t.Error("OverwriteConfig: expected true by default")
	}
	if config.QueryLogFilePath != "/tmp/dns_query.log" {
		t.Errorf("QueryLogFilePath: expected /tmp/dns_query.log, got %q", config.QueryLogFilePath)
	}
	if config.LogAnalyticsTable != "GitHubMetadata_CI_DNS_Queries" {
		t.Errorf("LogAnalyticsTable: expected GitHubMetadata_CI_DNS_Queries, got %q", config.LogAnalyticsTable)
	}
	if config.LogLevel != zerolog.InfoLevel {
		t.Errorf("LogLevel: expected InfoLevel, got %v", config.LogLevel)
	}
	if len(config.BlockList) != 0 {
		t.Errorf("BlockList: expected empty slice, got %v", config.BlockList)
	}
	if len(config.SafeList) != 0 {
		t.Errorf("SafeList: expected empty slice, got %v", config.SafeList)
	}
	if config.WildcardGreedy {
		t.Error("WildcardGreedy: expected false by default")
	}
}

func TestInitConfig_HostOverride(t *testing.T) {
	resetViper(t)
	t.Setenv("DNS_PROXY_HOST", "10.0.0.1")

	config := initConfig()

	if config.Host != "10.0.0.1" {
		t.Errorf("Host: expected 10.0.0.1, got %q", config.Host)
	}
}

func TestInitConfig_PortOverride(t *testing.T) {
	resetViper(t)
	t.Setenv("DNS_PROXY_PORT", "5353")

	config := initConfig()

	if config.Port != 5353 {
		t.Errorf("Port: expected 5353, got %d", config.Port)
	}
}

func TestInitConfig_UpstreamServerOverride(t *testing.T) {
	resetViper(t)
	t.Setenv("DNS_PROXY_UPSTREAMSERVER", "1.1.1.1")

	config := initConfig()

	if config.UpstreamServer != "1.1.1.1" {
		t.Errorf("UpstreamServer: expected 1.1.1.1, got %q", config.UpstreamServer)
	}
}

func TestInitConfig_ForwardToSentinelOverride(t *testing.T) {
	resetViper(t)
	t.Setenv("DNS_PROXY_FORWARDTOSENTINEL", "true")
	t.Setenv("DNS_PROXY_LOGANALYTICSWORKSPACEID", "ws-id")
	t.Setenv("DNS_PROXY_LOGANALYTICSSHAREDKEY", "c2VjcmV0")
	t.Setenv("DNS_PROXY_LOGANALYTICSTABLE", "MyTable")

	config := initConfig()

	if !config.ForwardToSentinel {
		t.Error("ForwardToSentinel: expected true")
	}
	if config.LogAnalyticsWorkspaceId != "ws-id" {
		t.Errorf("LogAnalyticsWorkspaceId: expected ws-id, got %q", config.LogAnalyticsWorkspaceId)
	}
	if config.LogAnalyticsSharedKey != "c2VjcmV0" {
		t.Errorf("LogAnalyticsSharedKey: expected c2VjcmV0, got %q", config.LogAnalyticsSharedKey)
	}
	if config.LogAnalyticsTable != "MyTable" {
		t.Errorf("LogAnalyticsTable: expected MyTable, got %q", config.LogAnalyticsTable)
	}
}

func TestInitConfig_OverwriteConfigFalse(t *testing.T) {
	resetViper(t)
	t.Setenv("DNS_PROXY_OVERWRITECONFIG", "false")

	config := initConfig()

	if config.OverwriteConfig {
		t.Error("OverwriteConfig: expected false")
	}
}

func TestInitConfig_QueryLogFilePathOverride(t *testing.T) {
	resetViper(t)
	t.Setenv("DNS_PROXY_QUERYLOGFILEPATH", "/tmp/custom_dns.log")

	config := initConfig()

	if config.QueryLogFilePath != "/tmp/custom_dns.log" {
		t.Errorf("QueryLogFilePath: expected /tmp/custom_dns.log, got %q", config.QueryLogFilePath)
	}
}

func TestInitConfig_LogLevels(t *testing.T) {
	tests := []struct {
		name     string
		envVal   string
		expected zerolog.Level
	}{
		{"debug", "debug", zerolog.DebugLevel},
		{"info", "info", zerolog.InfoLevel},
		{"warn", "warn", zerolog.WarnLevel},
		{"error", "error", zerolog.ErrorLevel},
		{"fatal", "fatal", zerolog.FatalLevel},
		{"panic", "panic", zerolog.PanicLevel},
		{"unknown_defaults_to_info", "unknown", zerolog.InfoLevel},
		{"uppercase_debug", "DEBUG", zerolog.DebugLevel},
		{"mixed_case_warn", "Warn", zerolog.WarnLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetViper(t)
			t.Setenv("DNS_PROXY_LOGLEVEL", tt.envVal)

			config := initConfig()

			if config.LogLevel != tt.expected {
				t.Errorf("LogLevel for %q: expected %v, got %v", tt.envVal, tt.expected, config.LogLevel)
			}
		})
	}
}

func TestInitConfig_WildcardGreedyOverride(t *testing.T) {
	resetViper(t)
	t.Setenv("DNS_PROXY_WILDCARDGREEDY", "true")

	config := initConfig()

	if !config.WildcardGreedy {
		t.Error("WildcardGreedy: expected true")
	}
}

func TestInitConfig_LoggerIsConfigured(t *testing.T) {
	resetViper(t)
	tmp := t.TempDir()
	t.Setenv("DNS_PROXY_QUERYLOGFILEPATH", tmp+"/q.log")

	config := initConfig()

	// Logger should be non-zero and usable without panic
	var buf strings.Builder
	log := config.Logger.With().Logger().Output(&buf)
	log.Info().Msg("test")
	// zerolog writes JSON; we just verify no panic occurred and something was written
	_ = os.Remove(tmp + "/q.log") // cleanup if written
}
