// certfiles-probe is a VALIDATION tool, not part of the collector and not shipped. It runs
// the Linux certificate sensor (cert-files) against any directory tree as if it were a Linux
// root, and writes the resulting CBOM, so the sensor can be checked against an independent
// oracle (testing/hostdiscovery/compare-certs.sh) on machines where the collector cannot run
// natively on Linux. Git for Windows ships a Linux-style tree with the Mozilla CA bundles,
// which makes it a real-world fixture on a Windows development machine.
//
// Usage: certfiles-probe ROOT [OUT.json]
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/discover"
	"github.com/offsetsecurity/cipherhorizon/internal/pqc"
	"github.com/offsetsecurity/cipherhorizon/internal/sense"
	_ "github.com/offsetsecurity/cipherhorizon/internal/sense/all"
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: certfiles-probe ROOT [OUT.json]")
		return 2
	}
	root, err := os.OpenRoot(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer root.Close() //nolint:errcheck // exiting
	res, err := discover.Run(context.Background(), sense.Default, discover.Options{
		FS: root.FS(), OS: "linux", Tier: "user", HostName: "probe", Enabled: []string{"cert-files"},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	assets, props, err := cbom.FromHostGraph(res.Graph, cbom.HostOptions{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	bom, _ := cbom.Build(assets, cbom.Options{Tool: cbom.Tool{Name: "certfiles-probe", Version: "dev"}, HostName: "probe", MetadataProperties: props})
	pqc.Annotate(bom, pqc.Analyze(bom))
	var buf bytes.Buffer
	if err := cbom.Encode(&buf, bom, true); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	out := os.Stdout
	if len(os.Args) > 2 {
		out, err = os.Create(os.Args[2]) //nolint:gosec // a developer tool: the output path is the operator's own argument
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer out.Close() //nolint:errcheck // exiting
	}
	_, _ = out.Write(buf.Bytes())
	for _, c := range res.Graph.Coverage {
		fmt.Fprintf(os.Stderr, "coverage: %s %s %s %v\n", c.Sensor, c.Status, c.Reason, c.Limits)
	}
	return 0
}
