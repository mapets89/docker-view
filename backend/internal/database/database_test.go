package database

import (
	"context"
	"database/sql"
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
