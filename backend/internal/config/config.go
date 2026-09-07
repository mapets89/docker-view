package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr, GatewayListenAddr, DBPath, StaticDir, GatewayURL, GatewaySecret string
	InstanceName, Environment                                                   string
	SessionTTL, TerminalIdle                                                    time.Duration
	LogTailDefault                                                              int
	CookieSecure, SecretMasking                                                 bool
	AllowedOrigins                                                              []string
	MaxBodyBytes                                                                int64
}

func Load(component string) (Config, error) {
	gatewaySecret := os.Getenv("DOCKERVIEW_GATEWAY_SECRET")
	if gatewaySecret == "" {
		if secretFile := os.Getenv("DOCKERVIEW_GATEWAY_SECRET_FILE"); secretFile != "" {
			if value, err := os.ReadFile(secretFile); err == nil {
				gatewaySecret = strings.TrimSpace(string(value))
			}
		}
	}
	c := Config{
		ListenAddr: env("DOCKERVIEW_LISTEN_ADDR", ":8080"), GatewayListenAddr: env("DOCKERVIEW_GATEWAY_LISTEN_ADDR", ":8081"),
		DBPath: env("DOCKERVIEW_DB_PATH", "./dockerview.db"), StaticDir: env("DOCKERVIEW_STATIC_DIR", "../frontend/dist"),
		GatewayURL: env("DOCKERVIEW_GATEWAY_URL", "http://127.0.0.1:8081"), GatewaySecret: gatewaySecret,
		InstanceName: env("DOCKERVIEW_INSTANCE_NAME", "DockerView"), Environment: env("DOCKERVIEW_ENVIRONMENT", "DEV"),
		SessionTTL: duration("DOCKERVIEW_SESSION_TTL", 12*time.Hour), TerminalIdle: duration("DOCKERVIEW_TERMINAL_IDLE_TIMEOUT", 15*time.Minute),
		LogTailDefault: integer("DOCKERVIEW_LOG_TAIL_DEFAULT", 500), CookieSecure: boolean("DOCKERVIEW_COOKIE_SECURE", true),
		SecretMasking: boolean("DOCKERVIEW_SECRET_MASKING", true), AllowedOrigins: split(env("DOCKERVIEW_ALLOWED_ORIGINS", "http://localhost:8080")),
		MaxBodyBytes: int64(integer("DOCKERVIEW_MAX_BODY_BYTES", 1<<20)),
	}
	if (component == "server" || component == "gateway") && len(c.GatewaySecret) < 32 {
		return c, fmt.Errorf("DOCKERVIEW_GATEWAY_SECRET must contain at least 32 characters")
	}
	return c, nil
}
func env(k, v string) string {
	if x := os.Getenv(k); x != "" {
		return x
	}
	return v
}
func duration(k string, v time.Duration) time.Duration {
	d, e := time.ParseDuration(os.Getenv(k))
	if e == nil && d > 0 {
		return d
	}
	return v
}
func integer(k string, v int) int {
	n, e := strconv.Atoi(os.Getenv(k))
	if e == nil {
		return n
	}
	return v
}
func boolean(k string, v bool) bool {
	b, e := strconv.ParseBool(os.Getenv(k))
	if e == nil {
		return b
	}
	return v
}
func split(v string) []string {
	var r []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			r = append(r, s)
		}
	}
	return r
}
