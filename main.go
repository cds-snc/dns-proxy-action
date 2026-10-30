package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// Initialize configuration
	config := initConfig()

	// Print config
	config.Logger.Info().
		Str("host", config.Host).
		Int64("port", config.Port).
		Strs("blocklist", config.BlockList).
		Strs("safelist", config.SafeList).
		Str("upstream_server", config.UpstreamServer).
		Bool("forward_to_sentinel", config.ForwardToSentinel).
		Str("sentinel_forwarding_mode", config.SentinelForwardingMode).
		Str("log_analytics_workspace_id", config.LogAnalyticsWorkspaceId).
		Str("log_analytics_table", config.LogAnalyticsTable).
		Str("sentinel_tenant_id", config.SentinelTenantID).
		Str("sentinel_client_id", config.SentinelClientID).
		Str("sentinel_dce_uri", config.SentinelDCEURI).
		Str("sentinel_dcr_immutable_id", config.SentinelDCRImmutableID).
		Str("sentinel_stream_name", config.SentinelStreamName).
		Bool("overwrite_config", config.OverwriteConfig).
		Str("query_log_file_path", config.QueryLogFilePath).
		Bool("wildcardgreedy", config.WildcardGreedy).
		Msg("Configuration")

	// Send queued Sentinel records before exiting
	go func() {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		<-signals
		config.SentinelForwarder.Flush(5 * time.Second)
		os.Exit(0)
	}()

	// Install the proxy server as the default DNS resolver
	if config.OverwriteConfig {
		replaceDNS(config)
	}

	// Start the DNS proxy server
	dnsProxyServer(config)
}
