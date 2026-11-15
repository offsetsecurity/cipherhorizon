package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/namefind"
)

// Seams for tests: the resolver, the dialer and the certificate log search of find.
var (
	findResolver namefind.Resolver   = net.DefaultResolver
	findCT       namefind.CTSearcher = namefind.CrtSh{}
	findDial                         = func(ctx context.Context, address string, port int) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
	}
)

const findUsage = `usage: cipherhorizon find [flags] DOMAIN

Finds the host names under a domain, resolves them and tries ports 443, 8443 and 22 (and 25 on
the domain's mail servers). Names go to standard output, one per line, so the result pipes into
tls scan or a file; what each source did goes to standard error. Flags go before the domain.
Look only under domains you own or are authorised to test.
`

// findCmd implements "cipherhorizon find": the name finding of the server, without a server.
func findCmd(ctx context.Context, args []string, env Env) int {
	fl := flag.NewFlagSet("find", flag.ContinueOnError)
	fl.SetOutput(env.Stderr)
	ct := fl.Bool("ct", false, "also search Certificate Transparency logs; this sends the domain name to "+findCT.Name())
	wordlist := fl.Bool("wordlist", false, "also try about 1,600 common labels (www, mail, vpn, dev-api ...)")
	listFile := fl.String("list", "", "also take names from this file, one per line (- for standard input)")
	noPorts := fl.Bool("no-ports", false, "do not try any port; print every name that resolves")
	targets := fl.Bool("targets", false, "print name:port for each port that answered instead of names, ready for tls scan and ssh scan")
	all := fl.Bool("all", false, "also print names that do not resolve")
	asJSON := fl.Bool("json", false, "print the whole result as JSON instead of names")
	timeout := fl.Duration("timeout", 30*time.Minute, "stop the run after this long")
	fl.Usage = func() {
		_, _ = fmt.Fprint(env.Stderr, findUsage)
		fl.PrintDefaults()
	}
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitFatal
	}
	if fl.NArg() != 1 {
		fl.Usage()
		return ExitFatal
	}
	if *targets && *noPorts {
		return fatalf(env, "--targets prints the ports that answered, so it cannot be combined with --no-ports")
	}
	sources := []string{namefind.SourceDNS}
	o := namefind.Options{Domain: fl.Arg(0), Resolver: findResolver, Dial: findDial, SkipPorts: *noPorts}
	if *ct {
		sources = append(sources, namefind.SourceCT)
		o.CT = findCT
	}
	if *wordlist {
		sources = append(sources, namefind.SourceWordlist)
	}
	if *listFile != "" {
		names, err := readNameList(*listFile)
		if err != nil {
			return fatalf(env, "reading the list: %v", err)
		}
		sources = append(sources, namefind.SourceList)
		o.List = names
	}
	o.Sources = sources
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	res, err := namefind.Run(ctx, o)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fatalf(env, "the run took longer than %s; raise --timeout", *timeout)
		}
		return fatalf(env, "%v", err)
	}
	if *asJSON {
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return fatalf(env, "%v", err)
		}
		return ExitOK
	}
	resolved, answering := 0, 0
	for _, n := range res.Names {
		if len(n.Addresses) > 0 {
			resolved++
		}
		if len(n.Ports) > 0 {
			answering++
		}
		switch {
		case *targets:
			for _, p := range n.Ports {
				_, _ = fmt.Fprintln(env.Stdout, net.JoinHostPort(n.Name, strconv.Itoa(p)))
			}
		case *all || len(n.Addresses) > 0:
			_, _ = fmt.Fprintln(env.Stdout, n.Name)
		}
	}
	writeFindSummary(env.Stderr, res, resolved, answering, *noPorts)
	return ExitOK
}

func readNameList(path string) ([]string, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close() //nolint:errcheck // read-only
		r = f
	}
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

var findSourceNames = map[string]string{
	namefind.SourceStored:   "names already held",
	namefind.SourceDNS:      "the domain's DNS records",
	namefind.SourceCT:       "certificate logs",
	namefind.SourceWordlist: "common names tried",
	namefind.SourceList:     "the supplied list",
}

// writeFindSummary says what each source did and what the run could not see.
func writeFindSummary(w io.Writer, res *namefind.Result, resolved, answering int, noPorts bool) {
	var b strings.Builder
	fmt.Fprintf(&b, "\n%s: %d names, %d resolve", res.Domain, len(res.Names), resolved)
	if !noPorts {
		fmt.Fprintf(&b, ", %d answer on a port", answering)
	}
	b.WriteString("\n")
	for _, s := range res.Sources {
		if s.ID == namefind.SourceStored {
			continue // the command line has no store
		}
		name := findSourceNames[s.ID]
		switch s.Status {
		case "ran":
			fmt.Fprintf(&b, "  %-26s %d names", name, s.Found)
			if s.Detail != "" {
				fmt.Fprintf(&b, " (%s)", s.Detail)
			}
		case "failed":
			fmt.Fprintf(&b, "  %-26s failed: %s", name, s.Detail)
		default:
			fmt.Fprintf(&b, "  %-26s not used", name)
		}
		b.WriteString("\n")
	}
	if res.Outside > 0 {
		fmt.Fprintf(&b, "  %d supplied names are not under %s and were left out\n", res.Outside, res.Domain)
	}
	if res.Truncated {
		fmt.Fprintf(&b, "  Stopped at %d names; there are more.\n", len(res.Names))
	}
	if len(res.WildcardCerts) > 0 {
		fmt.Fprintf(&b, "  Wildcard certificates (%s) cover names no source can list.\n", strings.Join(res.WildcardCerts, ", "))
	}
	b.WriteString("  No source knows every name: a name absent from all of them is not found. Your own DNS zone is the complete list.\n")
	_, _ = io.WriteString(w, b.String())
}
