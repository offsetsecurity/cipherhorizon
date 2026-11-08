package reportpdf

import (
	"fmt"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/pdf"
)

// clients is the client-simulation page (PRD-018): who connects, with what, and who does not, why.
func (x *endpoint) clients() {
	sims := x.ev.Clients
	if len(sims) == 0 {
		return
	}
	x.h2("Clients")
	ok, pq, noFS := 0, 0, 0
	var failing []string
	for _, c := range sims {
		if !c.Connects {
			failing = append(failing, c.Name)
			continue
		}
		ok++
		if c.PQ {
			pq++
		}
		if !c.ForwardSecrecy {
			noFS++
		}
	}
	line := fmt.Sprintf("%d of %d clients connect; %d with post-quantum key exchange; %d without forward secrecy.", ok, len(sims), pq, noFS)
	if len(failing) > 0 {
		x.callout(toneBad, bold(fmt.Sprintf("%s cannot connect: ", plural(len(failing), "client"))), body(strings.Join(failing, ", ")+". "+line))
	} else {
		x.callout(toneGood, bold("Every simulated client connects. "), body(line))
	}
	x.p(span("Simulated from what the scan enumerated and each client's published defaults; nothing was sent to the server.", pdf.Regular, smallSize, text2))
	var rows [][]pdf.Cell
	for _, c := range sims {
		if !c.Connects {
			rows = append(rows, []pdf.Cell{txt(c.Name, pdf.Bold, ink), chipCell("FAILS", toneBad), txt(c.Why, pdf.Regular, text2), txt("", pdf.Regular, ink), txt("", pdf.Regular, ink)})
			continue
		}
		props := "forward secrecy"
		t := toneOK
		if !c.ForwardSecrecy {
			props, t = "no forward secrecy", toneWarn
		}
		if c.PQ {
			props, t = "post-quantum · "+props, toneGood
		}
		group := c.Group
		if group == "" {
			group = "static RSA"
		}
		rows = append(rows, []pdf.Cell{txt(c.Name, pdf.Bold, ink), chipCell(c.Version, toneInfo), txt(c.Suite, pdf.Mono, ink), txt(group, pdf.Mono, ink), chipCell(strings.ToUpper(props), t)})
	}
	x.table([]pdf.Col{{Title: "Client", W: 1.6}, {Title: "Version", W: 0.8}, {Title: "Cipher suite", W: 2.6}, {Title: "Key exchange", W: 1.3}, {Title: "Properties", W: 1.5}}, rows)
}

var _ = eval.ClientSim{}
