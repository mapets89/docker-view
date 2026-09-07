package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/dockerview/dockerview/backend/internal/api"
	"github.com/dockerview/dockerview/backend/internal/config"
	"github.com/dockerview/dockerview/backend/internal/database"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)
	cfg, err := config.Load("server")
	if err != nil {
		log.Error("configuration rejected", "component", "server", "error", err)
		os.Exit(1)
	}
	store, err := database.Open(cfg.DBPath)
	if err != nil {
		log.Error("database initialization failed", "component", "server")
		os.Exit(1)
	}
	defer func() { _ = store.Close() }()
	if err = store.EnsureSettings(context.Background(), map[string]string{
		"instance_name":         cfg.InstanceName,
		"environment":           cfg.Environment,
		"terminal_idle_timeout": cfg.TerminalIdle.String(),
		"default_log_tail":      fmt.Sprint(cfg.LogTailDefault),
		"secret_masking":        strconv.FormatBool(cfg.SecretMasking),
	}); err != nil {
		log.Error("default settings initialization failed", "component", "server")
		os.Exit(1)
	}
	srv := &http.Server{Addr: cfg.ListenAddr, Handler: api.New(cfg, store).Router(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Info("DockerView Server listening", "component", "server", "address", cfg.ListenAddr)
	if err = srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
