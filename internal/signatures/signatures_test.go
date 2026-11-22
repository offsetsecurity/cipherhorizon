package signatures

import (
	"regexp"
	"strings"
	"testing"
)

func TestTheDatabaseIsValid(t *testing.T) {
	db, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(db.For("windows")) < 5 || len(db.For("linux")) < 5 {
		t.Errorf("signatures: %d windows, %d linux", len(db.For("windows")), len(db.For("linux")))
	}
	for _, s := range db.Signatures {
		if s.How == "" {
			t.Errorf("%s: no How", s.ID)
		}
	}
	e := db.Engine("linux")
	if !strings.HasPrefix(e, "signatures\t"+db.Version+"\n") || !strings.Contains(e, "sig\tlinux.packages\tpackage\tmatch=") || strings.Contains(e, "win.") {
		t.Errorf("engine lines:\n%s", e)
	}
}

func TestValidationRefusesWhatAnEngineMustNotDo(t *testing.T) {
	base := `{"version":"1","signatures":[{"id":"linux.x","platform":"linux","area":"ssh","title":"t","why":"w","capability":%s,"params":%s,"interpret":%s}]}`
	bad := map[string][3]string{
		"a command":        {`"command"`, `{"match":"x"}`, `"config"`},
		"wrong platform":   {`"registry"`, `{"key":"HKLM:\x","values":"a"}`, `"config"`},
		"unknown meaning":  {`"package"`, `{"match":"x"}`, `"anything"`},
		"missing param":    {`"lines"`, `{"paths":"/etc/x"}`, `"config"`},
		"extra param":      {`"package"`, `{"match":"x","exec":"rm"}`, `"package"`},
		"bad regex":        {`"package"`, `{"match":"("}`, `"package"`},
		"a key file":       {`"lines"`, `{"paths":"/etc/ssl/private/server.key","match":"."}`, `"config"`},
		"a key directory":  {`"certfiles"`, `{"dirs":"/etc/ssl/private"}`, `"certificate"`},
		"a tab in a value": {`"package"`, `{"match":"a\tb"}`, `"package"`},
		// PRD-019: a query is picked from the engine's table, never written; WireGuard folders hold keys.
		"an unknown query": {`"query"`, `{"query":"rm.everything"}`, `"platform"`},
		"a windows query":  {`"query"`, `{"query":"tls.cipher-suites"}`, `"platform"`},
		"wireguard":        {`"lines"`, `{"paths":"/etc/wireguard/*.conf","match":"^ListenPort"}`, `"vpn-config"`},
	}
	if _, err := Parse([]byte(strings.Replace(base, `"area":"ssh"`, `"area":"misc"`, 1))); err == nil {
		t.Error("an unknown area: accepted")
	}
	for name, v := range bad {
		doc := strings.Replace(strings.Replace(strings.Replace(base, "%s", v[0], 1), "%s", v[1], 1), "%s", v[2], 1)
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := strings.Replace(strings.Replace(strings.Replace(base, "%s", `"lines"`, 1), "%s", `{"paths":"/etc/ssh/ssh_host_*_key.pub","match":"^ssh-"}`, 1), "%s", `"ssh-host-key"`, 1)
	if _, err := Parse([]byte(ok)); err != nil {
		t.Errorf("a public host key file is allowed: %v", err)
	}
}

// No signature collects a setting that holds a secret: a key's password, the command that
// prints one, SASL password maps, a TSIG or IPsec secret, a directory password. Each line below
// is a setting of the software the signature reads, with a dummy value; the settings next to
// them still are collected.
func TestSignaturesLeaveSecretSettingsOut(t *testing.T) {
	db := MustLoad()
	secret := map[string][]string{
		"linux.dovecot.tls":       {"ssl_key_password = dummy-passphrase-1", "  ssl_key_password=dummy-passphrase-1", "ssl_server_key_password = dummy-passphrase-1", "ssl_client_key_password = dummy-passphrase-1"},
		"linux.dovecot.effective": {"ssl_key_password = # hidden, use -P to show it", "ssl_server_key_password = dummy-passphrase-1"},
		"linux.postgresql.tls":    {"ssl_passphrase_command = 'echo dummy-passphrase-2'", "  ssl_passphrase_command='/usr/local/bin/unlock dummy-passphrase-2'"},
		"linux.postfix.tls":       {"smtp_sasl_password_maps = static:user:dummy-password-3", "smtp_sasl_password_maps = hash:/etc/postfix/tls_passwd"},
		"linux.postfix.effective": {"smtp_sasl_password_maps = static:user:dummy-password-3", "smtp_sasl_password_maps = hash:/etc/postfix/tls_passwd", "lmtp_sasl_password_maps = static:user:dummy-password-3"},
		"linux.mysql.tls":         {"ssl-passphrase = dummy-passphrase-4", "ssl_passphrase=dummy-passphrase-4"},
		"linux.bind.dnssec":       {`    algorithm hmac-sha256; secret "ZHVtbXktc2VjcmV0LTU=";`, `secret "ZHVtbXktc2VjcmV0LTU=";`},
		"linux.ipsec.config":      {"secret = 0sZHVtbXktc2VjcmV0LTU="},
		"linux.ldap.tls":          {"rootpw dummy-password-6", "olcRootPW: dummy-password-6", "BINDPW dummy-password-6"},
	}
	for id, lines := range secret {
		s, ok := db.ByID(id)
		if !ok {
			t.Fatalf("no signature %s", id)
		}
		re := regexp.MustCompile(s.Params["match"])
		for _, l := range lines {
			if re.MatchString(l) {
				t.Errorf("%s collects %q", id, l)
			}
		}
	}
	kept := map[string][]string{
		"linux.dovecot.tls":       {"ssl = required", "ssl_cert = </etc/dovecot/cert.pem", "ssl_key = </etc/dovecot/key.pem", "ssl_min_protocol = TLSv1.2", "ssl_prefer_server_ciphers = yes", "ssl_server_cert_file = /etc/dovecot/cert.pem"},
		"linux.dovecot.effective": {"ssl = required", "ssl_cipher_list = HIGH", "ssl_server {", "ssl_prefer_server_ciphers = yes"},
		"linux.postgresql.tls":    {"ssl = on", "ssl_min_protocol_version = 'TLSv1.2'", "ssl_ciphers = 'HIGH'", "ssl_prefer_server_ciphers = on", "password_encryption = scram-sha-256"},
		"linux.postfix.tls":       {"smtpd_tls_security_level = may", "tls_high_cipherlist = HIGH", "smtp_sasl_auth_enable = yes", "smtp_sasl_security_options = noanonymous", "smtpd_sasl_path = private/auth"},
		"linux.postfix.effective": {"smtpd_tls_security_level = may", "smtp_tls_policy_maps = hash:/etc/postfix/tls_policy", "smtp_sasl_auth_enable = yes", "smtpd_sasl_type = dovecot", "cyrus_sasl_config_path = /etc/sasl2"},
		"linux.mysql.tls":         {"ssl-ca = /etc/mysql/ca.pem", "ssl_cert=/etc/mysql/cert.pem", "tls_version = TLSv1.2,TLSv1.3", "ssl", "require_secure_transport = ON", "ssl-cipher = ECDHE-RSA-AES256-GCM-SHA384"},
		"linux.bind.dnssec":       {"    algorithm hmac-sha256;", "algorithm hmac-sha512; // transfer key", "dnssec-validation auto;", "dnssec-policy default;"},
	}
	for id, lines := range kept {
		s, ok := db.ByID(id)
		if !ok {
			t.Fatalf("no signature %s", id)
		}
		re := regexp.MustCompile(s.Params["match"])
		for _, l := range lines {
			if !re.MatchString(l) {
				t.Errorf("%s no longer collects %q", id, l)
			}
		}
	}
}
