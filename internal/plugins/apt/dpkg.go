package apt

import (
	"bufio"
	"context"
	"io"
	"strings"
)

// pkg is the subset of a dpkg status stanza this plugin needs.
type pkg struct {
	Name    string
	Version string
	Arch    string
	Status  string // e.g. "install ok installed"
}

// installed reports whether the package's files are on disk. A stanza for a
// removed-but-configured package ("deinstall ok config-files") is history, not
// inventory.
func (p pkg) installed() bool {
	f := strings.Fields(p.Status)
	return len(f) == 3 && f[2] == "installed"
}

// parseStatus reads a dpkg status file (RFC 822-style stanzas separated by blank
// lines) and calls emit for every stanza that names a package. It reads only
// what it needs and ignores continuation lines, so multi-kilobyte descriptions
// cost nothing. On a read error it has already emitted every complete stanza
// before it.
func parseStatus(ctx context.Context, r io.Reader, emit func(pkg)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var cur pkg
	flush := func() {
		if cur.Name != "" {
			emit(cur)
		}
		cur = pkg{}
	}

	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if err := ctx.Err(); err != nil {
				return err
			}
			flush()
		case line[0] == ' ' || line[0] == '\t':
			// continuation of a multi-line field (Description, Depends, ...)
		default:
			key, val, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			val = strings.TrimSpace(val)
			switch key {
			case "Package":
				cur.Name = val
			case "Version":
				cur.Version = val
			case "Architecture":
				cur.Arch = val
			case "Status":
				cur.Status = val
			}
		}
	}
	flush() // the last stanza may lack a trailing blank line
	return sc.Err()
}
