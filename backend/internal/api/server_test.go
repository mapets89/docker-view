package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dockerview/dockerview/backend/internal/config"
	"github.com/dockerview/dockerview/backend/internal/database"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCreateUserAcceptsEnabledField(t *testing.T) {
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	admin, err := store.BootstrapAdmin(context.Background(), "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	server := New(config.Config{}, store)
	request := httptest.NewRequest(http.MethodPost, "http://localhost/api/v1/users", strings.NewReader(`{"username":"disabled-user","password":"secure password","roles":["role-viewer"],"enabled":false}`))
	request = request.WithContext(context.WithValue(request.Context(), sessionKey, database.Session{User: admin}))
	response := httptest.NewRecorder()
	server.createUser(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create user returned %d: %s", response.Code, response.Body.String())
	}
	var created database.User
	if err = json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Enabled {
		t.Fatal("enabled=false was ignored during user creation")
	}
	if len(created.Roles) != 1 || created.Roles[0] != "Viewer" {
		t.Fatalf("unexpected roles: %#v", created.Roles)
	}
}

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

func TestLogoutKeepsBootstrapClosedAndAuthResponsesUncached(t *testing.T) {
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	u, err := store.BootstrapAdmin(context.Background(), "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	token, csrf, err := store.CreateSession(context.Background(), u.ID, "", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{GatewaySecret: "01234567890123456789012345678901", MaxBodyBytes: 1 << 20, SessionTTL: time.Hour, AllowedOrigins: []string{"http://localhost"}}
	handler := New(cfg, store).Router()

	logout := httptest.NewRequest(http.MethodPost, "http://localhost/api/v1/auth/logout", nil)
	logout.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	logout.Header.Set("X-CSRF-Token", csrf)
	logout.Header.Set("Origin", "http://localhost")
	logoutResponse := httptest.NewRecorder()
	handler.ServeHTTP(logoutResponse, logout)
	if logoutResponse.Code != http.StatusNoContent {
		t.Fatalf("logout returned %d: %s", logoutResponse.Code, logoutResponse.Body.String())
	}

	status := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/status", nil)
	statusResponse := httptest.NewRecorder()
	handler.ServeHTTP(statusResponse, status)
	if statusResponse.Code != http.StatusOK {
		t.Fatalf("status returned %d: %s", statusResponse.Code, statusResponse.Body.String())
	}
	if !strings.Contains(statusResponse.Body.String(), `"needs_setup":false`) {
		t.Fatalf("logout reopened bootstrap: %s", statusResponse.Body.String())
	}
	if got := statusResponse.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("status Cache-Control = %q, want no-store", got)
	}
}

func TestStaticReplacesStaleHashedAssetAndRejectsUnknownAssets(t *testing.T) {
	staticDir := t.TempDir()
	assetDir := filepath.Join(staticDir, "_astro")
	if err := os.Mkdir(assetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staticDir, "index.html"), []byte("login"), 0o644); err != nil {
		t.Fatal(err)
	}
	const css = "body{color:teal}"
	if err := os.WriteFile(filepath.Join(assetDir, "global.CURRENT.css"), []byte(css), 0o644); err != nil {
		t.Fatal(err)
	}
	server := &Server{Cfg: config.Config{StaticDir: staticDir, StaticEnabled: true}}

	stale := httptest.NewRequest(http.MethodGet, "http://localhost/_astro/global.OLD.css", nil)
	staleResponse := httptest.NewRecorder()
	server.static(staleResponse, stale)
	if staleResponse.Code != http.StatusOK || staleResponse.Body.String() != css {
		t.Fatalf("stale asset returned %d %q", staleResponse.Code, staleResponse.Body.String())
	}
	if got := staleResponse.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/css") {
		t.Fatalf("stale CSS Content-Type = %q", got)
	}
	if got := staleResponse.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("stale asset Cache-Control = %q, want no-cache", got)
	}

	missing := httptest.NewRequest(http.MethodGet, "http://localhost/_astro/unknown.OLD.js", nil)
	missingResponse := httptest.NewRecorder()
	server.static(missingResponse, missing)
	if missingResponse.Code != http.StatusNotFound {
		t.Fatalf("unknown asset returned %d, want 404", missingResponse.Code)
	}
}

func TestStaticFilesDisabled(t *testing.T) {
	staticDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(staticDir, "index.html"), []byte("frontend"), 0600); err != nil {
		t.Fatal(err)
	}
	server := &Server{Cfg: config.Config{StaticDir: staticDir, StaticEnabled: false}}
	response := httptest.NewRecorder()
	server.static(response, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("static files disabled: got %d, want 404", response.Code)
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
	u, err := store.CreateUser(context.Background(), "viewer", "correct horse battery staple", []string{"role-viewer"}, true)
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
	events, err := store.ListAudit(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "CONTAINER_INSPECT" {
		t.Fatalf("explicit inspection audit = %#v", events)
	}
}

func TestRiskEnrichmentDoesNotWriteAudit(t *testing.T) {
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"Id":"test","Name":"/target","Config":{"Labels":{}},"HostConfig":{},"Mounts":[]}`)), Header: make(http.Header)}, nil
	})
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	user, err := store.CreateUser(context.Background(), "viewer", "correct horse battery staple", []string{"role-viewer"}, true)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := store.CreateSession(context.Background(), user.ID, "", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := New(config.Config{GatewayURL: "http://gateway", GatewaySecret: "01234567890123456789012345678901", MaxBodyBytes: 1 << 20, SessionTTL: time.Hour}, store)
	server.Gateway.HTTP = &http.Client{Transport: transport}
	request := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/containers/test/risk", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Router().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("risk enrichment returned %d: %s", response.Code, response.Body.String())
	}
	events, err := store.ListAudit(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("risk enrichment wrote audit events: %#v", events)
	}
}

func TestSecretRevealWritesOnlyRevealAudit(t *testing.T) {
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"Id":"test","Name":"/target","Config":{"Labels":{},"Env":["DB_PASSWORD=top-secret"]},"HostConfig":{},"Mounts":[]}`)), Header: make(http.Header)}, nil
	})
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	admin, err := store.BootstrapAdmin(context.Background(), "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := store.CreateSession(context.Background(), admin.ID, "", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := New(config.Config{GatewayURL: "http://gateway", GatewaySecret: "01234567890123456789012345678901", MaxBodyBytes: 1 << 20, SessionTTL: time.Hour, SecretMasking: true}, store)
	server.Gateway.HTTP = &http.Client{Transport: transport}
	request := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/containers/test/?reveal=true", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	server.Router().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("secret reveal returned %d: %s", response.Code, response.Body.String())
	}
	events, err := store.ListAudit(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "SECRET_REVEAL" {
		t.Fatalf("secret reveal audit = %#v", events)
	}
}
