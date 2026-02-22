package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

func NewAccountID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func HashPassword(password string) ([]byte, error) {
	password = strings.TrimSpace(password)
	if len(password) < 10 {
		return nil, errors.New("password too short (min 10 chars)")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	// Argon2id parameters: moderate defaults for MVP; tune based on VM CPU/RAM.
	hash := argon2.IDKey([]byte(password), salt, 2, 64*1024, 2, 32)
	buf := make([]byte, 0, 1+16+32)
	buf = append(buf, salt...)
	buf = append(buf, hash...)
	return buf, nil
}

func VerifyPassword(password string, stored []byte) (bool, error) {
	if len(stored) != 48 {
		return false, fmt.Errorf("invalid stored hash length")
	}
	salt := stored[:16]
	expected := stored[16:]
	hash := argon2.IDKey([]byte(password), salt, 2, 64*1024, 2, 32)
	if subtleConstantTimeCompare(hash, expected) {
		return true, nil
	}
	return false, nil
}

func subtleConstantTimeCompare(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func SignCookie(secret, value string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString([]byte(value)) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func VerifyCookie(secret, signed string) (string, bool) {
	parts := strings.Split(signed, ".")
	if len(parts) != 2 {
		return "", false
	}
	vb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(vb)
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return "", false
	}
	return string(vb), true
}
