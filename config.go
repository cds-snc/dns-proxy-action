package main

import (
	log "github.com/sirupsen/logrus"

	"github.com/spf13/viper"
)

type Config struct {
	BlockList      []string
	Host           string
	LogLevel       log.Level
	Port           int64
	SafeList       []string
	UpstreamServer string
}

func initConfig() *Config {
	viper.AutomaticEnv()
	viper.SetEnvPrefix("DNS_PROXY")

	var configuration Config

	// Set undefined variables
	viper.SetDefault("Host", "127.0.0.1")
	viper.SetDefault("Port", 53)
	viper.SetDefault("Blocklist", []string{})
	viper.SetDefault("Safelist", []string{})
	viper.SetDefault("UpstreamServer", "8.8.8.8")
	viper.SetDefault("LogLevel", "debug")

	configuration.Host = viper.GetString("Host")
	configuration.Port = viper.GetInt64("Port")
	configuration.BlockList = viper.GetStringSlice("Blocklist")
	configuration.SafeList = viper.GetStringSlice("Safelist")
	configuration.UpstreamServer = viper.GetString("UpstreamServer")

	// Log Level switch
	switch viper.GetString("LogLevel") {
	case "debug":
		configuration.LogLevel = log.DebugLevel
	case "info":
		configuration.LogLevel = log.InfoLevel
	case "warn":
		configuration.LogLevel = log.WarnLevel
	case "error":
		configuration.LogLevel = log.ErrorLevel
	case "fatal":
		configuration.LogLevel = log.FatalLevel
	case "panic":
		configuration.LogLevel = log.PanicLevel
	default:
		configuration.LogLevel = log.InfoLevel
	}

	return &configuration

}
