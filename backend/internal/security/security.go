package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const maxPasswordBytes = 1024

func RandomToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func ID() (string, error) { return RandomToken(18) }

func TokenHash(token string) string {
	s := sha256.Sum256([]byte(token))
	return hex.EncodeToString(s[:])
}

func HashPassword(password string) (string, error) {
	if len(password) < 6 {
		return "", errors.New("password must be at least 6 characters")
	}
	if len(password) > maxPasswordBytes {
		return "", errors.New("password is too long")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	memory, iterations, parallelism := uint32(64*1024), uint32(3), uint8(2)
	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func VerifyPassword(encoded, password string) bool {
	if len(password) > maxPasswordBytes {
		return false
	}
	p := strings.Split(encoded, "$")
	if len(p) != 6 || p[1] != "argon2id" || p[2] != "v=19" {
		return false
	}
	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(p[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	if memory > 256*1024 || iterations > 10 || parallelism > 8 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(p[4])
	expected, err2 := base64.RawStdEncoding.DecodeString(p[5])
	if err1 != nil || err2 != nil || len(salt) != 16 || len(expected) != 32 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

var sensitiveFragments = []string{"PASSWORD", "PASS", "SECRET", "TOKEN", "PRIVATE", "CREDENTIAL", "AUTH", "API_KEY", "ACCESS_KEY"}

func SensitiveKey(key string) bool {
	u := strings.ToUpper(key)
	if u == "DATABASE_URL" || u == "REDIS_URL" {
		return true
	}
	for _, fragment := range sensitiveFragments {
		if u == fragment || strings.Contains(u, "_"+fragment) || strings.HasPrefix(u, fragment+"_") {
			return true
		}
	}
	return false
}

func MaskEnv(values []string, reveal bool) []string {
	out := make([]string, 0, len(values))
	for _, item := range values {
		key, _, ok := strings.Cut(item, "=")
		if ok && SensitiveKey(key) && !reveal {
			out = append(out, key+"=********")
		} else {
			out = append(out, item)
		}
	}
	return out
}

func ConstantTimeSecret(expected, actual string) bool {
	if len(expected) < 32 || len(actual) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func ValidateUsername(s string) bool {
	if len(s) < 3 || len(s) > 64 {
		return false
	}
	for i, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9' && i > 0) || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func ValidateContainerID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		valid := r == '_' || r == '-' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if !valid {
			return false
		}
	}
	return !strings.Contains(s, "..")
}

func ParseBoundedInt(raw string, fallback, min, max int) int {
	v, err := strconv.Atoi(raw)
	if err != nil || v < min || v > max {
		return fallback
	}
	return v
}
