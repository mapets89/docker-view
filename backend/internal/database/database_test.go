package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"
)

func TestBootstrapSessionsAndRevocation(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	u, err := s.BootstrapAdmin(ctx, "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.BootstrapAdmin(ctx, "other", "another correct password"); err == nil {
		t.Fatal("bootstrap remained available")
	}
	token, _, err := s.CreateSession(ctx, u.ID, "127.0.0.1", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ResolveSession(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err = s.RevokeSession(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ResolveSession(ctx, token); err != sql.ErrNoRows {
		t.Fatalf("revoked session accepted: %v", err)
	}
}
func TestExpiredSessionRejected(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	u, err := s.BootstrapAdmin(context.Background(), "admin", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := s.CreateSession(context.Background(), u.ID, "", "", -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ResolveSession(context.Background(), token); err != sql.ErrNoRows {
		t.Fatalf("expired session accepted: %v", err)
	}
}

func TestAdministrativeListsReleaseSingleSQLiteConnection(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err = s.BootstrapAdmin(ctx, "admin", "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SavePolicy(ctx, Policy{Name: "test-policy", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ListUsers(ctx); err != nil {
		t.Fatalf("list users blocked with a single SQLite connection: %v", err)
	}
	if _, err = s.ListRoles(ctx); err != nil {
		t.Fatalf("list roles blocked with a single SQLite connection: %v", err)
	}
	if _, err = s.ListPolicies(ctx); err != nil {
		t.Fatalf("list policies blocked with a single SQLite connection: %v", err)
	}
}

func TestAuditRoundTrip(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	want := json.RawMessage(`{"terminal_session":"test-session"}`)
	if err = s.Audit(ctx, AuditEvent{
		Username: "admin",
		Action:   "EXEC_START",
		Result:   "success",
		Metadata: want,
	}); err != nil {
		t.Fatal(err)
	}
	events, err := s.ListAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one audit event, got %d", len(events))
	}
	if string(events[0].Metadata) != string(want) {
		t.Fatalf("unexpected metadata: got %s, want %s", events[0].Metadata, want)
	}
}
