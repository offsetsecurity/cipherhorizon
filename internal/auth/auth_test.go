package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	h, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "pbkdf2-sha256$600000$") {
		t.Fatalf("hash %q does not record its scheme and iterations", h)
	}
	if ok, re := Verify("correct horse battery staple", h); !ok || re {
		t.Fatalf("the right password: ok=%v rehash=%v", ok, re)
	}
	if ok, _ := Verify("correct horse battery stapl", h); ok {
		t.Fatal("a wrong password verified")
	}
	h2, _ := Hash("correct horse battery staple")
	if h == h2 {
		t.Fatal("two hashes of one password are equal: the salt is not random")
	}
	for _, bad := range []string{"", "plain", "pbkdf2-sha256$x$a$b", "md5$1$a$b", "pbkdf2-sha256$600000$!!$!!"} {
		if ok, _ := Verify("x", bad); ok {
			t.Errorf("%q verified", bad)
		}
	}
	weak, _ := hashWith("pw-for-old-hash", make([]byte, saltLen), 1000)
	if ok, re := Verify("pw-for-old-hash", weak); !ok || !re {
		t.Errorf("an old, weaker hash: ok=%v rehash=%v, want true true", ok, re)
	}
}

func TestPasswordPolicy(t *testing.T) {
	for _, c := range []struct{ pw, user string }{
		{"short", "ana"}, {"password1234", "ana"}, {"aaaaaaaaaaaaaa", "ana"}, {"my-name-is-ana-ok", "ana"}, {strings.Repeat("x", 257) + "y", "ana"},
	} {
		if err := CheckPassword(c.pw, c.user); !errors.Is(err, ErrWeakPassword) {
			t.Errorf("%q accepted", c.pw)
		}
	}
	if err := CheckPassword("violet amber harbour", "ana"); err != nil {
		t.Errorf("a good phrase refused: %v", err)
	}
}

func TestUsernames(t *testing.T) {
	for _, ok := range []string{"ana", "ana.ng@example.org", "ops_admin-2"} {
		if err := CheckUsername(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"ab", "has space", "<script>", strings.Repeat("a", 65)} {
		if CheckUsername(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTokensAndCodes(t *testing.T) {
	a, ha, _ := NewToken()
	b, _, _ := NewToken()
	if a == b || len(a) < 40 || ha != HashToken(a) || strings.Contains(ha, a) {
		t.Fatalf("tokens: %q %q hash %q", a, b, ha)
	}
	c, _ := NewSetupCode()
	if len(c) != 14 || !SameCode(strings.ToLower(strings.ReplaceAll(c, "-", " ")), c) || SameCode("AAAA-AAAA-AAAA", c) && c != "AAAA-AAAA-AAAA" {
		t.Fatalf("setup code %q", c)
	}
}
