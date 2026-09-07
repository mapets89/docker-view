package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dockerview/dockerview/backend/internal/config"
	"github.com/dockerview/dockerview/backend/internal/gateway"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)
	cfg, err := config.Load("gateway")
	if err != nil {
		log.Error("configuration rejected", "component", "gateway", "error", err)
		os.Exit(1)
	}
	docker, err := gateway.NewMobyService()
	if err != nil {
		log.Error("docker client initialization failed", "component", "gateway")
		os.Exit(1)
	}
	defer func() { _ = docker.Close() }()
	srv := &http.Server{Addr: cfg.GatewayListenAddr, Handler: gateway.NewHandler(docker, cfg.GatewaySecret).Router(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Info("DockerView Gateway listening", "component", "gateway", "address", cfg.GatewayListenAddr)
	if err = srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("gateway stopped", "error", err)
		os.Exit(1)
	}
}
