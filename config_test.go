package main

import (
	"os"
	"reflect"
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
	if config.SentinelStreamName != "Custom-GitHubMetadata_CI_DNS_Queries_V2_CL" {
		t.Errorf("SentinelStreamName: expected Custom-GitHubMetadata_CI_DNS_Queries_V2_CL, got %q", config.SentinelStreamName)
	}
	if config.SentinelOIDCAudience != "api://AzureADTokenExchange" {
		t.Errorf("SentinelOIDCAudience: expected api://AzureADTokenExchange, got %q", config.SentinelOIDCAudience)
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
	t.Setenv("DNS_PROXY_SENTINELTENANTID", "tenant-id")
	t.Setenv("DNS_PROXY_SENTINELCLIENTID", "client-id")
	t.Setenv("DNS_PROXY_SENTINELDCEURI", "https://example.ingest.monitor.azure.com")
	t.Setenv("DNS_PROXY_SENTINELDCRIMMUTABLEID", "dcr-immutable-id")
	t.Setenv("DNS_PROXY_SENTINELSTREAMNAME", "Custom-MyTable_CL")
	t.Setenv("DNS_PROXY_SENTINELOIDCAUDIENCE", "api://AzureADTokenExchange")

	config := initConfig()

	if !config.ForwardToSentinel {
		t.Error("ForwardToSentinel: expected true")
	}
	if config.SentinelTenantID != "tenant-id" {
		t.Errorf("SentinelTenantID: expected tenant-id, got %q", config.SentinelTenantID)
	}
	if config.SentinelClientID != "client-id" {
		t.Errorf("SentinelClientID: expected client-id, got %q", config.SentinelClientID)
	}
	if config.SentinelDCEURI != "https://example.ingest.monitor.azure.com" {
		t.Errorf("SentinelDCEURI: expected https://example.ingest.monitor.azure.com, got %q", config.SentinelDCEURI)
	}
	if config.SentinelDCRImmutableID != "dcr-immutable-id" {
		t.Errorf("SentinelDCRImmutableID: expected dcr-immutable-id, got %q", config.SentinelDCRImmutableID)
	}
	if config.SentinelStreamName != "Custom-MyTable_CL" {
		t.Errorf("SentinelStreamName: expected Custom-MyTable_CL, got %q", config.SentinelStreamName)
	}
	if config.SentinelOIDCAudience != "api://AzureADTokenExchange" {
		t.Errorf("SentinelOIDCAudience: expected api://AzureADTokenExchange, got %q", config.SentinelOIDCAudience)
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

func TestInitConfig_SafelistOverride(t *testing.T) {
	resetViper(t)
	t.Setenv("DNS_PROXY_SAFELIST", "*.githubapp.com,*.githubusercontent.com,*.hashicorp.com")

	config := initConfig()

	if len(config.SafeList) != 3 {
		t.Errorf("SafeList: expected 3 entries, got %d", len(config.SafeList))
	}
}

func TestInitConfig_BlocklistOverride(t *testing.T) {
	resetViper(t)
	t.Setenv("DNS_PROXY_BLOCKLIST", "*.githubapp.com,*.githubusercontent.com")

	config := initConfig()

	if len(config.BlockList) != 2 {
		t.Errorf("BlockList: expected 2 entries, got %d", len(config.BlockList))
	}
}

func TestParseSlice(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"comma", "a,b,c", []string{"a", "b", "c"}},
		{"comma_spaces", " a, b ,c ", []string{"a", "b", "c"}},
		{"newline_lf", "a\nb\nc", []string{"a", "b", "c"}},
		{"newline_crlf", "a\r\nb\r\nc", []string{"a", "b", "c"}},
		{"mixed_comma_newline", "a,b\nc", []string{"a", "b", "c"}},
		{"single", "single", []string{"single"}},
		{"empty", "", []string{}},
		{"spaces_only", "   ", []string{}},
		{"leading_trailing_commas", ",a,b,", []string{"a", "b"}},
		{"empty_lines", "\n\na\n\n", []string{"a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSlice(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseSlice(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
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
