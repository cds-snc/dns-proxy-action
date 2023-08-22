package main

func main() {
	// Initialize configuration
	config := initConfig()

	// Print config
	config.Logger.Debug().
		Str("host", config.Host).
		Int64("port", config.Port).
		Strs("blocklist", config.BlockList).
		Strs("safelist", config.SafeList).
		Str("upstream_server", config.UpstreamServer).
		Bool("forward_to_sentinel", config.ForwardToSentinel).
		Bool("overwrite_config", config.OverwriteConfig).
		Str("query_log_file_path", config.QueryLogFilePath).
		Msg("Configuration")

	// Install the proxy server as the default DNS resolver
	if config.OverwriteConfig {
		replaceDNS(config)
	}

	// Start the DNS proxy server
	dnsProxyServer(config)
}
