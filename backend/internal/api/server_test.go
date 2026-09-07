package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dockerview/dockerview/backend/internal/config"
	"github.com/dockerview/dockerview/backend/internal/database"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMutableRouteRequiresCSRF(t *testing.T) {
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	u, err := store.BootstrapAdmin(context.Background(), "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := store.CreateSession(context.Background(), u.ID, "", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{GatewaySecret: "01234567890123456789012345678901", MaxBodyBytes: 1 << 20, SessionTTL: time.Hour, AllowedOrigins: []string{"http://localhost"}}
	handler := New(cfg, store).Router()
	r := httptest.NewRequest(http.MethodPost, "http://localhost/api/v1/auth/logout", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	r.Header.Set("Origin", "http://localhost")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("missing CSRF returned %d", w.Code)
	}
}

func TestSecretPermissionStillMasksWhenGlobalMaskingDisabled(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-DockerView-Gateway-Secret") == "" {
			t.Fatal("gateway request omitted authentication")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"Id":"test","Name":"/target","Config":{"Labels":{},"Env":["DB_PASSWORD=top-secret"]},"HostConfig":{},"Mounts":[]}`)), Header: make(http.Header)}, nil
	})
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	u, err := store.CreateUser(context.Background(), "viewer", "correct horse battery staple", []string{"role-viewer"})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := store.CreateSession(context.Background(), u.ID, "", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{GatewayURL: "http://gateway", GatewaySecret: "01234567890123456789012345678901", MaxBodyBytes: 1 << 20, SessionTTL: time.Hour, SecretMasking: false}
	r := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/containers/test/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w := httptest.NewRecorder()
	server := New(cfg, store)
	server.Gateway.HTTP = &http.Client{Transport: transport}
	server.Router().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("inspect returned %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "top-secret") || !strings.Contains(w.Body.String(), "DB_PASSWORD=********") {
		t.Fatalf("response did not enforce secret.view masking: %s", w.Body.String())
	}
}
