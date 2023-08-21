package main

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

type Config struct {
	BlockList               []string
	ForwardToSentinel       bool
	Host                    string
	LogAnalyticsWorkspaceId string
	LogAnalyticsSharedKey   string
	LogAnalyticsTable       string
	LogLevel                zerolog.Level
	Logger                  zerolog.Logger
	OverwriteConfig         bool
	Port                    int64
	QueryLogFilePath        string
	SafeList                []string
	UpstreamServer          string
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
	viper.SetDefault("ForwardToSentinel", false)
	viper.SetDefault("LogAnalyticsWorkspaceId", "")
	viper.SetDefault("LogAnalyticsSharedKey", "")
	viper.SetDefault("LogAnalyticsTable", "GitHubMetadata_CI_DNS_Queries")
	viper.SetDefault("OverwriteConfig", true)
	viper.SetDefault("QueryLogFilePath", "/tmp/dns_query.log")

	configuration.Host = viper.GetString("Host")
	configuration.Port = viper.GetInt64("Port")
	configuration.BlockList = viper.GetStringSlice("Blocklist")
	configuration.SafeList = viper.GetStringSlice("Safelist")
	configuration.UpstreamServer = viper.GetString("UpstreamServer")
	configuration.ForwardToSentinel = viper.GetBool("ForwardToSentinel")
	configuration.LogAnalyticsWorkspaceId = viper.GetString("LogAnalyticsWorkspaceId")
	configuration.LogAnalyticsSharedKey = viper.GetString("LogAnalyticsSharedKey")
	configuration.LogAnalyticsTable = viper.GetString("LogAnalyticsTable")
	configuration.OverwriteConfig = viper.GetBool("OverwriteConfig")
	configuration.QueryLogFilePath = viper.GetString("QueryLogFilePath")

	// Log Level switch
	switch viper.GetString("LogLevel") {
	case "debug":
		configuration.LogLevel = zerolog.DebugLevel
	case "info":
		configuration.LogLevel = zerolog.InfoLevel
	case "warn":
		configuration.LogLevel = zerolog.WarnLevel
	case "error":
		configuration.LogLevel = zerolog.ErrorLevel
	case "fatal":
		configuration.LogLevel = zerolog.FatalLevel
	case "panic":
		configuration.LogLevel = zerolog.PanicLevel
	default:
		configuration.LogLevel = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(configuration.LogLevel)

	// Create multiple output steams for zerolog
	multi := zerolog.MultiLevelWriter(QueryLogger{config: &configuration}, SentinelForwarder{config: &configuration}, os.Stdout)

	logger := zerolog.New(multi).With().Timestamp().Logger()

	configuration.Logger = logger

	return &configuration

}
