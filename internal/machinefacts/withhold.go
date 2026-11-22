package machinefacts

import (
	"regexp"
	"strings"
	"unicode"
)

// Withheld replaces the value of a setting that holds a secret. The setting's name stays, so a
// reader still sees that it is set.
const Withheld = "(value withheld)"

// Settings that hold a secret are kept by name with their value withheld: a password, a
// passphrase or the command that prints one, a shared secret, a private key written inline.
// The signatures already leave such settings out; this applies the same rule to every facts
// file, including one written by an older engine or edited by hand, before anything from it
// reaches a CBOM.

// secretWords are the name fragments of such settings, matched on the name lower-cased with
// everything but letters and digits removed (smtp_sasl_password_maps → smtpsaslpasswordmaps).
var secretWords = regexp.MustCompile(`password|passwd|passphrase|secret|privatekey|presharedkey|apikey|credentials?$|pw$`)

// secretTokens are whole words of a name that mark a secret (pin-value, wpa_psk).
var secretTokens = map[string]bool{"pin": true, "psk": true, "pwd": true}

// policyNames are settings named after passwords whose values are policy, not secrets.
var policyNames = map[string]bool{
	"passwordauthentication": true, // sshd: yes | no
	"permitemptypasswords":   true, // sshd
	"passwordencryption":     true, // PostgreSQL: the hash it stores passwords with
	"disablepasswordchange":  true, // Netlogon
	"maximumpasswordage":     true, // Netlogon
	"encryptpasswords":       true, // Samba
}

// secretName reports whether a setting, attribute or flag of this name holds a secret.
func secretName(name string) bool {
	var compact strings.Builder
	for _, r := range strings.ToLower(name) {
		if r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			compact.WriteRune(r)
		}
	}
	c := compact.String()
	if c == "" || policyNames[c] {
		return false
	}
	// A setting that names where a secret is kept (ssl_password_file, tls-private-key-file)
	// holds a path, not the secret.
	for _, ref := range []string{"file", "files", "path", "dir", "directory"} {
		if strings.HasSuffix(c, ref) {
			return false
		}
	}
	if secretWords.MatchString(c) {
		return true
	}
	for _, w := range nameWords(name) {
		if secretTokens[w] {
			return true
		}
	}
	return false
}

// nameWords splits a name into lower-case words at punctuation and camelCase boundaries.
func nameWords(name string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(name)
	for i, r := range rs {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && i > 0 && unicode.IsLower(rs[i-1]):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return words
}

// pamTypes and pamControls recognise a PAM rule ("password required pam_unix.so sha512"), whose
// first word is a module type, not a setting.
var (
	pamTypes    = map[string]bool{"auth": true, "account": true, "password": true, "session": true}
	pamControls = regexp.MustCompile(`^(required|requisite|sufficient|optional|include|substack|\[.*)$`)
)

// nameToken is a setting name at the start of a statement ("ssl_key_password", "olcRootPW").
// settingName is a name before "=" or ":" that may hold spaces or a list dash, as in
// "ldap admin password = …" or "- --etcd-password=…".
var (
	nameToken   = regexp.MustCompile(`^[A-Za-z0-9_.-]*[A-Za-z0-9]`)
	settingName = regexp.MustCompile(`^[\sA-Za-z0-9_.-]*[A-Za-z0-9]\s*$`)
	separator   = regexp.MustCompile(`^\s*[=:]?\s*`)
)

// attribute finds name=value pairs inside a line: XML attributes, command-line flags, module
// arguments (password="…", --db-password=…, bindpw=…).
var attribute = regexp.MustCompile(`(^|[\s,{(<])(-{0,2}[A-Za-z][A-Za-z0-9_.-]*)(\s*=\s*)("[^"]*"|'[^']*'|[^\s;,>"']+)`)

// withholdLine returns a configuration or query line with the value of every secret-bearing
// setting in it replaced by Withheld. Statements separated by ";" are read one by one, so
// "algorithm hmac-sha256; secret "…";" keeps its algorithm.
func withholdLine(line string) string {
	parts := splitStatements(line)
	changed := false
	for i, p := range parts {
		if p == ";" {
			continue
		}
		if q := withholdStatement(p); q != p {
			parts[i], changed = q, true
		}
	}
	if !changed {
		return line
	}
	return strings.Join(parts, "")
}

// withholdStatement withholds the value of one statement whose name holds a secret, or else the
// values of secret-bearing name=value pairs inside it.
func withholdStatement(st string) string {
	trimmed := strings.TrimLeft(st, " 	")
	lead := st[:len(st)-len(trimmed)]
	fields := strings.Fields(trimmed)
	pam := len(fields) >= 2 && pamTypes[strings.TrimPrefix(fields[0], "-")] && pamControls.MatchString(fields[1])
	if !pam {
		if name := nameToken.FindString(trimmed); name != "" && secretName(name) {
			rest := trimmed[len(name):]
			sep := separator.FindString(rest)
			if rest[len(sep):] != "" {
				return lead + name + sep + Withheld
			}
			return st
		}
		if i := strings.IndexAny(trimmed, "=:"); i > 0 && settingName.MatchString(trimmed[:i]) && secretName(trimmed[:i]) {
			rest := trimmed[i+1:]
			if strings.TrimSpace(rest) != "" {
				return lead + trimmed[:i+1] + rest[:len(rest)-len(strings.TrimLeft(rest, " 	"))] + Withheld
			}
			return st
		}
	}
	idx := attribute.FindAllStringSubmatchIndex(st, -1)
	if idx == nil {
		return st
	}
	var b strings.Builder
	last := 0
	for _, m := range idx {
		name := st[m[4]:m[5]]
		if !secretName(name) {
			continue
		}
		value := st[m[8]:m[9]]
		b.WriteString(st[last:m[8]])
		switch {
		case strings.HasPrefix(value, `"`):
			b.WriteString(`"` + Withheld + `"`)
		case strings.HasPrefix(value, `'`):
			b.WriteString(`'` + Withheld + `'`)
		default:
			b.WriteString(Withheld)
		}
		last = m[9]
	}
	b.WriteString(st[last:])
	return b.String()
}

// splitStatements splits a line at semicolons outside quotes, keeping each ";" as its own part.
func splitStatements(line string) []string {
	var parts []string
	var quote rune
	start := 0
	for i, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == ';':
			parts = append(parts, line[start:i], ";")
			start = i + 1
		}
	}
	return append(parts, line[start:])
}

// withholdItem applies the rule to one item a signature returned: the text of a configuration
// or query line, and the value of a registry value whose name holds a secret.
func withholdItem(it *Item) {
	switch it.Kind {
	case "line", "query":
		if len(it.Fields) >= 2 {
			it.Fields[1] = withholdLine(it.Fields[1])
		}
	case "registry":
		if len(it.Fields) >= 3 && it.Fields[2] != "" && secretName(it.Fields[1]) {
			it.Fields[2] = Withheld
		}
	}
}
