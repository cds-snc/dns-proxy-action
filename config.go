package main

import (
	"os"
	"strings"

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
	WildcardGreedy          bool
}

func initConfig() *Config {
	viper.AutomaticEnv()
	viper.SetEnvPrefix("DNS_PROXY")

	var configuration Config

	// Set undefined variables
	viper.SetDefault("Host", "172.17.0.1") // This ensures that docker also binds to the proxy
	viper.SetDefault("Port", 53)
	viper.SetDefault("Blocklist", []string{})
	viper.SetDefault("Safelist", []string{})
	viper.SetDefault("UpstreamServer", "8.8.8.8")
	viper.SetDefault("LogLevel", "info")
	viper.SetDefault("ForwardToSentinel", false)
	viper.SetDefault("LogAnalyticsWorkspaceId", "")
	viper.SetDefault("LogAnalyticsSharedKey", "")
	viper.SetDefault("LogAnalyticsTable", "GitHubMetadata_CI_DNS_Queries")
	viper.SetDefault("OverwriteConfig", true)
	viper.SetDefault("QueryLogFilePath", "/tmp/dns_query.log")
	viper.SetDefault("WildcardGreedy", false)

	configuration.Host = viper.GetString("Host")
	configuration.Port = viper.GetInt64("Port")
	configuration.BlockList = parseSlice(viper.GetString("Blocklist"))
	configuration.SafeList = parseSlice(viper.GetString("Safelist"))
	configuration.UpstreamServer = viper.GetString("UpstreamServer")
	configuration.ForwardToSentinel = viper.GetBool("ForwardToSentinel")
	configuration.LogAnalyticsWorkspaceId = viper.GetString("LogAnalyticsWorkspaceId")
	configuration.LogAnalyticsSharedKey = viper.GetString("LogAnalyticsSharedKey")
	configuration.LogAnalyticsTable = viper.GetString("LogAnalyticsTable")
	configuration.OverwriteConfig = viper.GetBool("OverwriteConfig")
	configuration.QueryLogFilePath = viper.GetString("QueryLogFilePath")
	configuration.WildcardGreedy = viper.GetBool("WildcardGreedy")

	// Log Level switch
	switch strings.ToLower(viper.GetString("LogLevel")) {
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
	multi := zerolog.MultiLevelWriter(QueryLogger{config: &configuration}, SentinelForwarder{config: &configuration}, zerolog.ConsoleWriter{Out: os.Stderr})

	logger := zerolog.New(multi).With().Timestamp().Logger()

	configuration.Logger = logger

	return &configuration

}

func parseSlice(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return []string{}
	}
	// Split on comma and newline (handle CRLF) and trim each entry. Ignore empty lines.
	var parts []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		p = strings.TrimSpace(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}
