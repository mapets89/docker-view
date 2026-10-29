package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dockerview/dockerview/backend/internal/config"
	"github.com/dockerview/dockerview/backend/internal/database"
)

type rejectingProvider struct{ calls int }

func (p *rejectingProvider) Authenticate(context.Context, string, string) (database.User, bool, error) {
	p.calls++
	return database.User{}, false, nil
}

func (p *rejectingProvider) Name() string { return "rejecting-test-provider" }

func TestLoginThrottleBlocksFifthFailureForTwentySeconds(t *testing.T) {
	now := time.Date(2026, time.October, 29, 12, 0, 0, 0, time.UTC)
	throttle := newLoginThrottle(5, 20*time.Second)
	throttle.now = func() time.Time { return now }

	for attempt := 1; attempt < 5; attempt++ {
		if retryAfter := throttle.failed("admin|127.0.0.1"); retryAfter != 0 {
			t.Fatalf("attempt %d blocked early for %s", attempt, retryAfter)
		}
	}
	if retryAfter := throttle.failed("admin|127.0.0.1"); retryAfter != 20*time.Second {
		t.Fatalf("fifth failure retry-after = %s, want 20s", retryAfter)
	}
	if retryAfter := throttle.blocked("admin|127.0.0.1"); retryAfter != 20*time.Second {
		t.Fatalf("blocked retry-after = %s, want 20s", retryAfter)
	}

	now = now.Add(19 * time.Second)
	if retryAfter := throttle.blocked("admin|127.0.0.1"); retryAfter != time.Second {
		t.Fatalf("retry-after after 19s = %s, want 1s", retryAfter)
	}
	now = now.Add(time.Second)
	if retryAfter := throttle.blocked("admin|127.0.0.1"); retryAfter != 0 {
		t.Fatalf("throttle remained blocked after cooldown: %s", retryAfter)
	}
}

func TestLoginThrottleClearsFailuresAfterSuccess(t *testing.T) {
	throttle := newLoginThrottle(5, 20*time.Second)
	for attempt := 0; attempt < 4; attempt++ {
		if retryAfter := throttle.failed("admin|127.0.0.1"); retryAfter != 0 {
			t.Fatalf("attempt %d blocked early", attempt+1)
		}
	}
	throttle.clear("admin|127.0.0.1")
	if retryAfter := throttle.failed("admin|127.0.0.1"); retryAfter != 0 {
		t.Fatalf("failure count was not cleared: %s", retryAfter)
	}
}

func TestLoginEndpointBlocksOnFifthFailure(t *testing.T) {
	store, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	server := New(config.Config{MaxBodyBytes: 1 << 20, SessionTTL: time.Hour}, store)
	provider := &rejectingProvider{}
	server.Auth = provider
	handler := server.Router()

	for attempt := 1; attempt <= 6; attempt++ {
		request := httptest.NewRequest(http.MethodPost, "http://localhost/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"wrong"}`))
		request.RemoteAddr = "192.0.2.10:4567"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)

		wantStatus := http.StatusUnauthorized
		if attempt >= 5 {
			wantStatus = http.StatusTooManyRequests
		}
		if response.Code != wantStatus {
			t.Fatalf("attempt %d returned %d, want %d: %s", attempt, response.Code, wantStatus, response.Body.String())
		}
		if attempt == 5 && response.Header().Get("Retry-After") != "20" {
			t.Fatalf("fifth attempt Retry-After = %q, want 20", response.Header().Get("Retry-After"))
		}
	}
	if provider.calls != 5 {
		t.Fatalf("authentication called %d times, want 5", provider.calls)
	}
}
