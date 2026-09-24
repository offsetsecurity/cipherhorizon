package evidence

import "strings"

// ArtefactKey is the canonical key of a file: its host-relative, forward-slash
// path with the user-profile segment tokenised (see RedactPath).
func ArtefactKey(relPath string) string { return "file:" + strings.ToLower(relPath) }

// AlgorithmKey is the canonical key of a catalogue algorithm.
func AlgorithmKey(id string) string { return "algo:" + id }

// RedactPath tokenises the user-profile segment of a host-relative path so that
// no user name is ever emitted: "Users/alice/AppData/x" -> "Users/%USER%/AppData/x",
// "home/alice/x" -> "home/%USER%/x". It expects forward slashes and no leading slash.
// The Windows built-in profile roots that are not user names are left alone.
func RedactPath(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) >= 2 {
		switch strings.ToLower(parts[0]) {
		case "users", "home":
			if !builtinProfile(parts[1]) {
				parts[1] = "%USER%"
			}
		}
	}
	return strings.Join(parts, "/")
}

// builtinProfile reports directories under Users that are not a person.
func builtinProfile(name string) bool {
	switch strings.ToLower(name) {
	case "public", "default", "default user", "all users", "%user%":
		return true
	}
	return false
}
