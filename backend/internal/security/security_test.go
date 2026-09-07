package security

import "testing"

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("a good password phrase")
	if err != nil || !VerifyPassword(h, "a good password phrase") || VerifyPassword(h, "wrong password") {
		t.Fatal("password verification failed")
	}
}

func TestPasswordMinimumLength(t *testing.T) {
	if _, err := HashPassword("123456"); err != nil {
		t.Fatalf("six-character password rejected: %v", err)
	}
	if _, err := HashPassword("12345"); err == nil {
		t.Fatal("five-character password accepted")
	}
}
func TestMaskEnv(t *testing.T) {
	got := MaskEnv([]string{"NODE_ENV=dev", "DB_PASSWORD=hunter2", "MONKEY=value", "API_TOKEN=x", "DATABASE_URL=postgres://secret"}, false)
	if got[1] != "DB_PASSWORD=********" || got[2] != "MONKEY=value" || got[3] != "API_TOKEN=********" || got[4] != "DATABASE_URL=********" {
		t.Fatalf("unexpected masking: %#v", got)
	}
}
func TestConstantTimeSecretRejectsWeakExpected(t *testing.T) {
	if ConstantTimeSecret("short", "short") {
		t.Fatal("weak shared secret accepted")
	}
}
