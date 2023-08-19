package main

import (
	log "github.com/sirupsen/logrus"
)

func main() {
	// Initialize configuration
	config := initConfig()
	log.SetLevel(config.LogLevel)

	// Print config
	log.WithFields(log.Fields{
		"Host":           config.Host,
		"Port":           config.Port,
		"Blocklist":      config.BlockList,
		"Safelist":       config.SafeList,
		"UpstreamServer": config.UpstreamServer,
		"LogLevel":       config.LogLevel,
	}).Debugln("Configuration")

	// Install the proxy server as the default DNS resolver
	replaceDNS(config)

	// Start the DNS proxy server
	dnsProxyServer(config)
}
