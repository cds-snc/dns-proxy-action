package main

import (
	log "github.com/sirupsen/logrus"
)

func main() {
	// Initialize configuration
	config := initConfig()
	log.SetLevel(config.LogLevel)

	// Install the proxy server as the default DNS resolver
	replaceDNS(config)

	// Start the DNS proxy server
	dnsProxyServer(config)
}
