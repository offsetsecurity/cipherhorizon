package machinefacts

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
)

// A facts file as an older engine could write it: settings that hold secrets next to the
// settings that are wanted. The values are dummies.
const secretSettingsFacts = `cipherhorizon-machine-facts	3
script	linux-sh	3.0.0
host	name	mail-01
host	os	linux
host	privilege	admin
signatures	2026.11.09
fact	linux.dovecot.tls	line	/etc/dovecot/conf.d/10-ssl.conf	ssl_key_password = DUMMY-PASSPHRASE-1
fact	linux.dovecot.tls	line	/etc/dovecot/conf.d/10-ssl.conf	ssl_min_protocol = TLSv1.2
fact	linux.dovecot.effective	query	dovecot.ssl	ssl_server_key_password=DUMMY-PASSPHRASE-1
fact	linux.postgresql.tls	line	/etc/postgresql/16/main/postgresql.conf	ssl_passphrase_command = 'echo DUMMY-PASSPHRASE-2'
fact	linux.postgresql.tls	line	/etc/postgresql/16/main/postgresql.conf	password_encryption = scram-sha-256
fact	linux.postfix.tls	line	/etc/postfix/main.cf	smtp_sasl_password_maps = static:user:DUMMY-PASSWORD-3
fact	linux.postfix.tls	line	/etc/postfix/main.cf	smtp_sasl_auth_enable = yes
fact	linux.postfix.effective	query	postfix.tls	smtp_sasl_password_maps = static:user:DUMMY-PASSWORD-3
fact	linux.bind.dnssec	line	/etc/bind/named.conf	    algorithm hmac-sha256; secret "DUMMY-SECRET-4";
fact	linux.ldap.tls	line	/etc/ldap/slapd.conf	rootpw DUMMY-PASSWORD-5
fact	linux.ldap.tls	line	/etc/ldap/slapd.d/cn=config.ldif	olcRootPW: DUMMY-PASSWORD-5
fact	linux.kubernetes.apiserver	line	/etc/kubernetes/manifests/kube-apiserver.yaml	    - --etcd-password=DUMMY-PASSWORD-6
fact	linux.kubernetes.apiserver	line	/etc/kubernetes/manifests/kube-apiserver.yaml	    - --tls-private-key-file=/etc/kubernetes/pki/apiserver.key
fact	linux.nginx.tls	line	/etc/nginx/nginx.conf	ssl_password_file /etc/nginx/ssl.pass;
fact	linux.ipsec.config	line	/etc/swanctl/swanctl.conf	secret = 0sDUMMY-SECRET-7
fact	linux.ssh.server-config	line	/etc/ssh/sshd_config	PasswordAuthentication no
fact	linux.ssh.server-effective	query	sshd.effective	passwordauthentication no
fact	linux.platform.password-hashing	line	/etc/pam.d/common-password	password [success=1 default=ignore] pam_unix.so obscure yescrypt
fact	linux.platform.password-hashing	line	/etc/pam.d/common-auth	auth required pam_ldap.so bindpw=DUMMY-PASSWORD-8
fact	linux.openvpn.config	line	/etc/openvpn/server.conf	<connection password="DUMMY-PASSWORD-9" proto="udp">
`

// The value of a setting that holds a secret never reaches the CBOM, whatever engine wrote the
// facts file: the setting is kept by name, its value withheld, and the settings around it are
// unchanged.
func TestSecretSettingValuesAreWithheld(t *testing.T) {
	f, err := Parse([]byte(secretSettingsFacts))
	if err != nil {
		t.Fatal(err)
	}
	bom, err := ToCBOM(context.Background(), f, Options{ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := cbom.EncodeSpec(&buf, bom, cbom.Spec16, true); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "DUMMY-") {
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "DUMMY-") {
				t.Errorf("a secret value reached the CBOM: %s", strings.TrimSpace(l))
			}
		}
	}
	byRef := componentsByRef(bom)
	dovecot := byRef["config/tls/linux.dovecot.tls"]
	wantProp(t, dovecot, "setting:ssl_key_password", Withheld)
	wantProp(t, dovecot, "setting:ssl_min_protocol", "TLSv1.2")
	pg := byRef["config/tls/linux.postgresql.tls"]
	wantProp(t, pg, "setting:ssl_passphrase_command", Withheld)
	wantProp(t, pg, "setting:password_encryption", "scram-sha-256")
	postfix := byRef["config/tls/linux.postfix.tls"]
	wantProp(t, postfix, "setting:smtp_sasl_password_maps", Withheld)
	wantProp(t, postfix, "setting:smtp_sasl_auth_enable", "yes")
	wantProp(t, byRef["config/linux.bind.dnssec"], "setting:algorithm", "hmac-sha256")
	for _, want := range []string{"/etc/kubernetes/pki/apiserver.key", "/etc/nginx/ssl.pass", "yescrypt"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q, which is not a secret, is missing from the CBOM", want)
		}
	}

	// Line by line, the rule keeps names and policy and withholds only secret values.
	for in, want := range map[string]string{
		"ssl_key_password = x1":                           "ssl_key_password = " + Withheld,
		"ssl_key_password=x1":                             "ssl_key_password=" + Withheld,
		"SSLPassPhraseDialog exec:/usr/bin/x1":            "SSLPassPhraseDialog " + Withheld,
		`algorithm hmac-sha256; secret "x1";`:             `algorithm hmac-sha256; secret ` + Withheld + `;`,
		`secret "a;b";`:                                   `secret ` + Withheld + `;`,
		"    - --etcd-password=x1":                        "    - --etcd-password=" + Withheld,
		`<site name="a"><vd userName="u" password="x1"/>`: `<site name="a"><vd userName="u" password="` + Withheld + `"/>`,
		"ldap admin password = x1":                        "ldap admin password = " + Withheld,
		"wpa_psk x1":                                      "wpa_psk " + Withheld,
		"PasswordAuthentication yes":                      "PasswordAuthentication yes",
		"password_encryption = scram-sha-256":             "password_encryption = scram-sha-256",
		"password required pam_unix.so sha512":            "password required pam_unix.so sha512",
		"ssl_password_file /etc/nginx/pass;":              "ssl_password_file /etc/nginx/pass;",
		"ssl_key = </etc/dovecot/private/key.pem":         "ssl_key = </etc/dovecot/private/key.pem",
		"Key Container = te-1234":                         "Key Container = te-1234",
		"ssl_key_password =":                              "ssl_key_password =",
	} {
		if got := withholdLine(in); got != want {
			t.Errorf("withholdLine(%q) = %q, want %q", in, got, want)
		}
	}

	// A registry value named for a secret is withheld; a password policy value is not.
	for _, c := range []struct{ name, value, want string }{
		{"DefaultPassword", "x1", Withheld},
		{"DisablePasswordChange", "0", "0"},
		{"MaximumPasswordAge", "30", "30"},
		{"Enabled", "1", "1"},
	} {
		it := Item{Kind: "registry", Fields: []string{`HKLM:\SOFTWARE\X`, c.name, c.value}}
		withholdItem(&it)
		if it.Fields[2] != c.want {
			t.Errorf("registry %s = %q, want %q", c.name, it.Fields[2], c.want)
		}
	}
}
