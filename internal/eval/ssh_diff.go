package eval

import (
	"fmt"
	"sort"

	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/registry"
)

// SSH change areas: readiness and the baseline verdict first, then the algorithm lists, then findings.
var sshAreaOrder = map[string]int{"readiness": 0, "baseline": 1, "kex": 2, "host-key": 3, "cipher": 4, "mac": 5, "finding": 6}

// sshWeak reports whether an algorithm is one an SSH rule judges (so adding it is worse).
func sshWeak(kind, name string) bool {
	a, ok := registry.Lookup(kind, name)
	if !ok {
		return false
	}
	switch kind {
	case registry.KindKex:
		return a.Hash == "SHA-1" || a.GroupBits > 0 && a.GroupBits < 2048
	case registry.KindHostKey:
		return a.Key == "DSA" || a.Hash == "SHA-1"
	case registry.KindCipher:
		return a.Cipher == "none" || a.Cipher == "RC4" || a.Cipher == "DES" || a.BlockBits == 64 || a.Mode == "CBC"
	case registry.KindMAC:
		return a.Hash == "none" || a.Hash == "MD5" || a.TagBits > 0 && a.TagBits < 128
	}
	return false
}

func sshImpact(kind, name string, added bool) Impact {
	a, _ := registry.Lookup(kind, name)
	switch {
	case a.PQ && added, sshWeak(kind, name) && !added:
		return Better
	case a.PQ, sshWeak(kind, name):
		return Worse
	}
	return Neutral
}

// CompareSSH reports what changed from one SSH scan to a later one (PRD-008 REQ-SHE-7).
func CompareSSH(from, to *sshprobe.Report, fromEv, toEv Evaluation) Diff {
	var ch []Change
	if fromEv.Readiness.Level != toEv.Readiness.Level {
		imp := Worse
		if toEv.Readiness.Level > fromEv.Readiness.Level {
			imp = Better
		}
		ch = append(ch, Change{Area: "readiness", Kind: "changed", Subject: "PQC readiness level",
			Before: fmt.Sprintf("L%d %s", fromEv.Readiness.Level, fromEv.Readiness.Label),
			After:  fmt.Sprintf("L%d %s", toEv.Readiness.Level, toEv.Readiness.Label), Impact: imp})
	}
	if before, after := baselineText(fromEv.Baseline), baselineText(toEv.Baseline); before != after && fromEv.Baseline != nil && toEv.Baseline != nil {
		imp := Neutral
		switch fb, tb := fromEv.Baseline, toEv.Baseline; {
		case tb.Meets && !fb.Meets, !tb.Meets && !fb.Meets && len(tb.Changes) < len(fb.Changes):
			imp = Better
		case fb.Meets && !tb.Meets, !tb.Meets && !fb.Meets && len(tb.Changes) > len(fb.Changes):
			imp = Worse
		}
		ch = append(ch, Change{Area: "baseline", Kind: "changed", Subject: toEv.Baseline.Title, Before: before, After: after, Impact: imp})
	}
	lists := func(r *sshprobe.Report) map[string][]string {
		a := r.Algorithms
		if a == nil {
			a = &sshprobe.Algorithms{}
		}
		return map[string][]string{registry.KindKex: a.Kex, registry.KindHostKey: a.HostKey,
			registry.KindCipher: mergeOrdered(a.CipherC2S, a.CipherS2C), registry.KindMAC: mergeOrdered(a.MACC2S, a.MACS2C)}
	}
	area := map[string]string{registry.KindKex: "kex", registry.KindHostKey: "host-key", registry.KindCipher: "cipher", registry.KindMAC: "mac"}
	fl, tl := lists(from), lists(to)
	for kind, ar := range area {
		for _, n := range tl[kind] {
			if !contains(fl[kind], n) {
				ch = append(ch, Change{Area: ar, Kind: "added", Subject: n, Impact: sshImpact(kind, n, true)})
			}
		}
		for _, n := range fl[kind] {
			if !contains(tl[kind], n) {
				ch = append(ch, Change{Area: ar, Kind: "removed", Subject: n, Impact: sshImpact(kind, n, false)})
			}
		}
	}
	// A host key of the same type with a different fingerprint was replaced: neutral, but worth seeing.
	byType := func(r *sshprobe.Report) map[string]string {
		m := map[string]string{}
		for _, k := range r.HostKeys {
			m[k.Type] = k.Fingerprint
		}
		return m
	}
	fk, tk := byType(from), byType(to)
	for t, fp := range tk {
		if old, ok := fk[t]; ok && old != fp {
			ch = append(ch, Change{Area: "host-key", Kind: "changed", Subject: t + " host key replaced", Before: old, After: fp, Impact: Neutral})
		}
	}
	ff, tf := findingSet(fromEv), findingSet(toEv)
	for _, k := range union(keysF(ff), keysF(tf)) {
		f, inF := ff[k]
		t, inT := tf[k]
		switch {
		case inT && !inF:
			imp := Worse
			if t.Severity == Info {
				imp = Neutral
			}
			ch = append(ch, Change{Area: "finding", Kind: "added", Subject: t.ID + ": " + t.Title, After: string(t.Severity), Impact: imp})
		case inF && !inT:
			imp := Better
			if f.Severity == Info {
				imp = Neutral
			}
			ch = append(ch, Change{Area: "finding", Kind: "removed", Subject: f.ID + ": " + f.Title, Before: string(f.Severity), Impact: imp})
		}
	}
	sort.SliceStable(ch, func(i, j int) bool {
		if sshAreaOrder[ch[i].Area] != sshAreaOrder[ch[j].Area] {
			return sshAreaOrder[ch[i].Area] < sshAreaOrder[ch[j].Area]
		}
		return ch[i].Subject < ch[j].Subject
	})
	d := Diff{Changes: ch}
	if d.Changes == nil {
		d.Changes = []Change{}
	}
	for _, c := range ch {
		switch c.Impact {
		case Better:
			d.Better++
		case Worse:
			d.Worse++
		default:
			d.Neutral++
		}
	}
	if len(ch) == 0 {
		d.Summary = "No changes between these scans."
	} else {
		d.Summary = fmt.Sprintf("%d change(s): %d better, %d worse, %d neutral.", len(ch), d.Better, d.Worse, d.Neutral)
	}
	if from.Incomplete || to.Incomplete {
		d.Summary += " One of the scans was incomplete, so some differences may be artefacts of the probing."
	}
	return d
}

// baselineText is a conformance in a few words, for a diff line.
func baselineText(c *Conformance) string {
	switch {
	case c == nil || !c.Judged:
		return "not judged"
	case c.Meets:
		return "meets"
	case len(c.Changes) == 1:
		return "does not meet (1 change)"
	}
	return fmt.Sprintf("does not meet (%d changes)", len(c.Changes))
}
