package knowledge

import (
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/algo"
)

func TestParseDebian(t *testing.T) {
	for in, want := range map[string]Version{
		"3.0.13-0ubuntu3.4":    {3, 0, 13},
		"1:2.4.4-2ubuntu17":    {2, 4, 4},
		"3.5.1-1":              {3, 5, 1},
		"1.1.1w-0+deb11u1":     {1, 1, 1},
		"3.5.0~rc1-1":          {3, 5, 0},
		"2.4":                  {2, 4, 0},
		"3":                    {3, 0, 0},
		"1.10.3-2build1":       {1, 10, 3},
		"3.0.2-0ubuntu1.18":    {3, 0, 2},
		"0~20240101+git-1":     {0, 0, 0},
		"2:1.4.5-1+b1":         {1, 4, 5},
		"1.0.1e-2+deb7u20":     {1, 0, 1},
		"3.5.4-1~deb13u1":      {3, 5, 4},
		"1:3.5.0-0ubuntu2:bad": {3, 5, 0},
	} {
		got, ok := ParseDebian(in)
		if !ok || got != want {
			t.Errorf("ParseDebian(%q) = %v,%v want %v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "abc", "-1", "v3.5"} {
		if _, ok := ParseDebian(bad); ok {
			t.Errorf("ParseDebian(%q) parsed; want !ok", bad)
		}
	}
}

func TestParseFile(t *testing.T) {
	for in, want := range map[string]Version{"3.5.7": {3, 5, 7}, "3.5.7.0": {3, 5, 7}, "2.4": {2, 4, 0}} {
		if got, ok := ParseFile(in); !ok || got != want {
			t.Errorf("ParseFile(%q) = %v,%v want %v", in, got, ok, want)
		}
	}
	if got, ok := ParseFile("  1.1.1  "); !ok || got != (Version{1, 1, 1}) {
		t.Errorf("surrounding space not trimmed: %v %v", got, ok)
	}
	if _, ok := ParseFile("unknown"); ok {
		t.Error("parsed a non-version")
	}
}

func TestAtLeast(t *testing.T) {
	min := Version{3, 5, 0}
	for v, want := range map[Version]bool{
		{3, 5, 0}: true, {3, 5, 1}: true, {3, 6, 0}: true, {4, 0, 0}: true,
		{3, 4, 9}: false, {3, 0, 13}: false, {2, 9, 9}: false, {1, 1, 1}: false,
	} {
		if got := v.AtLeast(min); got != want {
			t.Errorf("%v.AtLeast(%v) = %v, want %v", v, min, got, want)
		}
	}
}

// Invariants over the table itself.
func TestFamiliesAreSound(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range Families {
		if seen[f.ID] {
			t.Errorf("duplicate family %q", f.ID)
		}
		seen[f.ID] = true
		if f.Kind != KindLibrary && f.Kind != KindApplication {
			t.Errorf("%s: kind %q", f.ID, f.Kind)
		}
		if len(f.Caps) > 0 && len(f.Basis) == 0 {
			t.Errorf("%s: capabilities without a cited basis", f.ID)
		}
		for _, c := range f.Caps {
			for _, id := range c.Algos {
				if _, ok := algo.Lookup(id); !ok {
					t.Errorf("%s: algorithm %q is not in the catalogue", f.ID, id)
				}
			}
		}
	}
}

func TestRecognizePackage(t *testing.T) {
	for _, name := range []string{"bash", "coreutils", "libc6", "libssl-dev", "libssl-doc", "openssl-provider-legacy", "gnupg-l10n", "libgpg-error0", "libcurl4"} {
		if f := RecognizePackage(name); f != nil {
			t.Errorf("%q wrongly matched crypto family %q", name, f.ID)
		}
	}
	for name, family := range map[string]string{
		"openssl": "openssl", "libssl3": "openssl", "libssl3t64": "openssl", "libssl1.1": "openssl", "libssl1.0.0": "openssl",
		"gnupg": "gnupg", "gpg": "gnupg", "gnupg2": "gnupg", "gpgv": "gnupg",
		"libgnutls30t64": "gnutls", "libnettle8t64": "nettle", "libhogweed6": "nettle", "libssh-4": "libssh", "libssh2-1": "libssh",
		"openssh-server": "openssh", "libcrypt1": "libxcrypt", "python3-cryptography": "python-cryptography",
	} {
		if f := RecognizePackage(name); f == nil || f.ID != family {
			t.Errorf("RecognizePackage(%q) = %v, want family %q", name, f, family)
		}
	}
}

func TestRecognizeFile(t *testing.T) {
	for name, family := range map[string]string{
		"libcrypto-3-x64.dll": "openssl", "libssl-3-x64.dll": "openssl", "libcrypto-1_1.dll": "openssl", "libeay32.dll": "openssl",
		"msys-crypto-3.dll": "openssl", "nss3.dll": "nss", "libgnutls-30.dll": "gnutls", "libnettle-8.dll": "nettle",
		"libsodium.dll": "libsodium", "gpg.exe": "gnupg", "libgcrypt-20.dll": "libgcrypt",
		"openssl.exe": "openssl", "msys-gnutls-30.dll": "gnutls", "msys-nettle-9.dll": "nettle", "msys-hogweed-7.dll": "nettle", "cyggcrypt-20.dll": "libgcrypt",
	} {
		if f := RecognizeFile(name); f == nil || f.ID != family {
			t.Errorf("RecognizeFile(%q) = %v, want family %q", name, f, family)
		}
	}
	// Lookalikes must not match: a VLC *plugin* that links GnuTLS is not GnuTLS;
	// notes, keys and backups are not libraries.
	for _, name := range []string{"libgnutls_plugin.dll", "libcrypto-3-x64.dll.txt", "libcrypto.key", "id_rsa", "libcrypto-3-x64.dll.bak", "mylibssl.dll", "libssl.pem", "openssl.exe.bak", "msys-gnutls-plugin.dll", "openssl.cnf", "openssl.exe.config"} {
		if f := RecognizeFile(name); f != nil {
			t.Errorf("RecognizeFile(%q) wrongly matched %q", name, f.ID)
		}
	}
}

func TestCapabilities(t *testing.T) {
	openssl, _ := ByID("openssl")
	has := func(ids []string, want string) bool {
		for _, id := range ids {
			if id == want {
				return true
			}
		}
		return false
	}
	old := openssl.Capabilities(Version{3, 0, 13}, true)
	if !has(old, "RSA") || has(old, "ML-KEM-768") {
		t.Errorf("3.0.13: %v", old)
	}
	cur := openssl.Capabilities(Version{3, 5, 1}, true)
	if !has(cur, "ML-KEM-768") || len(cur) != 9+18 {
		t.Errorf("3.5.1: %d algorithms", len(cur))
	}
	// Unreadable version: ungated only, never assumed.
	unk := openssl.Capabilities(Version{}, false)
	if !has(unk, "RSA") || has(unk, "ML-KEM-768") {
		t.Errorf("unknown version: %v", unk)
	}
	gpg, _ := ByID("gnupg")
	if g := gpg.Capabilities(Version{1, 4, 23}, true); has(g, "ECDSA") || !has(g, "RSA") {
		t.Errorf("gpg 1.4: %v", g)
	}
	if g := gpg.Capabilities(Version{2, 4, 4}, true); !has(g, "Ed25519") {
		t.Errorf("gpg 2.4: %v", g)
	}
	gcrypt, _ := ByID("libgcrypt")
	if len(gcrypt.Capabilities(Version{1, 10, 3}, true)) != 0 {
		t.Error("an uncurated family was credited with capabilities")
	}
}

func TestKindForFile(t *testing.T) {
	ssl, _ := ByID("openssl")
	if ssl.KindForFile("openssl.exe") != KindApplication || ssl.KindForFile("libcrypto-3-x64.dll") != KindLibrary {
		t.Error("openssl.exe is an application; its DLLs are libraries")
	}
}

func TestKindForSplitsExecutablesFromLibraries(t *testing.T) {
	ssl, _ := ByID("openssl")
	if ssl.KindFor("openssl") != KindApplication || ssl.KindFor("libssl3t64") != KindLibrary {
		t.Error("openssl CLI is an application; libssl* are libraries")
	}
	ssh, _ := ByID("openssh")
	if ssh.KindFor("openssh-server") != KindApplication {
		t.Error("openssh-server is an application")
	}
}

func TestMappingCarriesCitationsAndVersion(t *testing.T) {
	f, _ := ByID("openssl")
	id, cites := f.Mapping()
	if id != "capability/openssl@"+KBVersion || len(cites) == 0 {
		t.Errorf("mapping = %q %v", id, cites)
	}
}
