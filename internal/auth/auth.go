// Package auth holds the decisions behind signing in (ADR-0018): how a password is hashed and
// checked, what a password must be, and how session tokens and setup codes are made. It has no
// state and no I/O; internal/store keeps the accounts and internal/server enforces the rules.
package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// PBKDF2-HMAC-SHA256 with the iteration count OWASP's Password Storage Cheat Sheet gives for it
// (600,000), a 16-byte random salt and a 32-byte key. It is in Go's standard library and
// FIPS 140-approved, so it needs no new module (the rule in CONTRIBUTING).
const (
	Iterations = 600_000
	saltLen    = 16
	keyLen     = 32
	scheme     = "pbkdf2-sha256"
)

// Password limits (NIST SP 800-63B §3.1.1: a length floor, a generous ceiling, no composition
// rules, and a check against commonly used passwords).
const (
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

// ErrWeakPassword wraps every policy refusal; its message says what to change.
var ErrWeakPassword = errors.New("password refused")

// Hash returns the encoded hash of a password: scheme$iterations$salt$key.
func Hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return hashWith(password, salt, Iterations)
}

func hashWith(password string, salt []byte, iter int) (string, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, iter, keyLen)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("%s$%d$%s$%s", scheme, iter, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// Verify reports whether password matches the encoded hash, in constant time for the key
// comparison. needsRehash is true when the hash was made with weaker parameters than today's.
func Verify(password, encoded string) (ok, needsRehash bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != scheme {
		return false, false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > 10_000_000 {
		return false, false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false, false
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false, false
	}
	return subtle.ConstantTimeCompare(key, want) == 1, iter < Iterations
}

// dummyHash is checked when the username does not exist, so a failed sign-in takes the same
// time whether or not the account exists.
var dummyHash = func() string {
	h, err := hashWith("not a real password", make([]byte, saltLen), Iterations)
	if err != nil {
		panic(err)
	}
	return h
}()

// VerifyNothing spends the time a real check would.
func VerifyNothing(password string) { Verify(password, dummyHash) }

// common is a short list of the most used passwords that also pass the length rule; the full
// breached-password lists are too large to embed, so this catches only the obvious.
var common = map[string]bool{
	"password1234": true, "123456789012": true, "qwertyuiop12": true, "passwordpassword": true,
	"administrator": true, "letmein123456": true, "welcome12345": true, "changeme1234": true,
	"iloveyou1234": true, "111111111111": true, "000000000000": true, "abcdefghijkl": true,
	"cipherhorizon": true, "password123!": true, "qwerty123456": true, "1q2w3e4r5t6y": true,
}

// CheckPassword applies the policy; the error says what to change.
func CheckPassword(password, username string) error {
	n := utf8.RuneCountInString(password)
	switch {
	case n < MinPasswordLen:
		return fmt.Errorf("%w: use at least %d characters (a phrase of a few words is easiest to remember)", ErrWeakPassword, MinPasswordLen)
	case n > MaxPasswordLen:
		return fmt.Errorf("%w: use at most %d characters", ErrWeakPassword, MaxPasswordLen)
	case !utf8.ValidString(password):
		return fmt.Errorf("%w: it is not valid text", ErrWeakPassword)
	}
	lower := strings.ToLower(password)
	if u := strings.ToLower(strings.TrimSpace(username)); u != "" && strings.Contains(lower, u) {
		return fmt.Errorf("%w: it must not contain the username", ErrWeakPassword)
	}
	if common[lower] {
		return fmt.Errorf("%w: it is one of the most commonly used passwords", ErrWeakPassword)
	}
	first, _ := utf8.DecodeRuneInString(password)
	if strings.Count(password, string(first)) == n {
		return fmt.Errorf("%w: it repeats one character", ErrWeakPassword)
	}
	return nil
}

// CheckUsername allows 3–64 letters, digits and . _ - @ (an e-mail address works).
func CheckUsername(u string) error {
	if n := utf8.RuneCountInString(u); n < 3 || n > 64 {
		return errors.New("a username has 3 to 64 characters")
	}
	for _, r := range u {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("._-@", r) {
			return errors.New("a username may use letters, digits and . _ - @ only")
		}
	}
	return nil
}

// NewToken returns a random session token (256 bits) and the hash under which it is stored.
func NewToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken is how a session token is looked up: only its SHA-256 is stored.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewSetupCode returns a one-time code for first-run setup: 12 characters from an alphabet
// without look-alikes, grouped for reading off a console (about 60 bits).
func NewSetupCode() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(alphabet[int(c)%len(alphabet)])
	}
	return sb.String(), nil
}

// SameCode compares a typed setup code with the real one, ignoring case, spaces and dashes,
// in constant time.
func SameCode(typed, real string) bool {
	norm := func(s string) string {
		return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(s))
	}
	return subtle.ConstantTimeCompare([]byte(norm(typed)), []byte(norm(real))) == 1
}
