package evidence

import (
	"fmt"
	"sort"
)

// Node is one thing on the host and every observation made about it.
type Node struct {
	Subject      Subject
	Observations []*Observation
}

// Present returns the observed `present` observations of the node.
func (n *Node) Present() []*Observation {
	var out []*Observation
	for _, o := range n.Observations {
		if o.Origin == OriginObserved && o.Claim.Rung == RungPresent && o.Outcome == OutcomeObserved {
			out = append(out, o)
		}
	}
	return out
}

// Derived returns the derived observations of the node.
func (n *Node) Derived() []*Observation {
	var out []*Observation
	for _, o := range n.Observations {
		if o.Origin == OriginDerived {
			out = append(out, o)
		}
	}
	return out
}

// PresentQuality is the strongest method quality among the node's observed
// `present` observations, and whether there is one. It is what decides whether a
// capability may be derived: a name match alone is not enough (ADR-0002).
func (n *Node) PresentQuality() (Quality, bool) {
	best, found := QualityHeuristic, false
	for _, o := range n.Present() {
		q, err := QualityOf(*o)
		if err != nil {
			continue
		}
		if !found || q.rank() > best.rank() {
			best, found = q, true
		}
	}
	return best, found
}

// Graph holds the normalised evidence for one host: one Node per subject key,
// every observation kept (nothing is averaged), plus the coverage each sensor reported.
type Graph struct {
	Host     Host
	Coverage []Coverage

	nodes map[string]*Node
	byID  map[string]*Observation
}

// NewGraph returns an empty graph for host.
func NewGraph(host Host) *Graph {
	return &Graph{Host: host, nodes: map[string]*Node{}, byID: map[string]*Observation{}}
}

// Add validates o and inserts it. A derived observation's BasedOn must already be
// in the graph, and neither it nor its relations may be stronger than the
// weakest observation it rests on (the central rule). Adding an identical
// observation twice is a no-op.
func (g *Graph) Add(o Observation) error {
	if err := Validate(o); err != nil {
		return fmt.Errorf("observation %s (%s %s): %w", o.ID, o.Subject.Kind, o.Subject.Key, err)
	}
	if _, dup := g.byID[o.ID]; dup {
		return nil
	}
	if o.Origin == OriginDerived {
		weakest := MinClass()
		for _, id := range o.BasedOn {
			in, ok := g.byID[id]
			if !ok {
				return fmt.Errorf("derived observation %s rests on %s, which is not in the graph", o.ID, id)
			}
			weakest = MinClass(weakest, ClassOf(in.Claim))
		}
		if ClassOf(o.Claim) > weakest {
			return fmt.Errorf("derived observation %s claims %s but rests only on %s evidence", o.ID, ClassOf(o.Claim), weakest)
		}
		for i, r := range o.Relations {
			if ClassOf(r.Claim) > weakest {
				return fmt.Errorf("derived observation %s relation %d claims %s but rests only on %s evidence", o.ID, i, ClassOf(r.Claim), weakest)
			}
		}
	}

	cp := o
	g.byID[o.ID] = &cp
	n, ok := g.nodes[o.Subject.Key]
	if !ok {
		n = &Node{Subject: Subject{Kind: o.Subject.Kind, Key: o.Subject.Key}}
		g.nodes[o.Subject.Key] = n
	}
	n.Observations = append(n.Observations, &cp)
	g.remerge(n)
	return nil
}

// remerge recomputes the node's subject: attributes from the strongest-quality
// observation win, ties broken by method ID so the result is deterministic.
func (g *Graph) remerge(n *Node) {
	obs := append([]*Observation(nil), n.Observations...)
	sort.SliceStable(obs, func(i, j int) bool {
		qi, _ := QualityOf(*obs[i])
		qj, _ := QualityOf(*obs[j])
		if qi.rank() != qj.rank() {
			return qi.rank() < qj.rank() // weakest first, so the strongest is applied last
		}
		return obs[i].Method < obs[j].Method
	})
	merged := Subject{Kind: n.Subject.Kind, Key: n.Subject.Key}
	for _, o := range obs {
		if o.Subject.Name != "" {
			merged.Name = o.Subject.Name
		}
		for k, v := range o.Subject.Attrs {
			if merged.Attrs == nil {
				merged.Attrs = map[string]string{}
			}
			merged.Attrs[k] = v
		}
	}
	n.Subject = merged
	sort.Slice(n.Observations, func(i, j int) bool { return n.Observations[i].ID < n.Observations[j].ID })
}

// AddBatch adds every observation and the coverage of a batch. It stops at the
// first invalid observation: a sensor that breaks the contract is a bug, not a
// partial result.
func (g *Graph) AddBatch(b Batch) error {
	for _, o := range b.Observations {
		if err := g.Add(o); err != nil {
			return err
		}
	}
	g.Coverage = append(g.Coverage, b.Coverage...)
	return nil
}

// Node returns the node with the given subject key.
func (g *Graph) Node(key string) (*Node, bool) {
	n, ok := g.nodes[key]
	return n, ok
}

// Nodes returns every node, sorted by key.
func (g *Graph) Nodes() []*Node {
	out := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject.Key < out[j].Subject.Key })
	return out
}

// Observation returns an observation by ID.
func (g *Graph) Observation(id string) (*Observation, bool) {
	o, ok := g.byID[id]
	return o, ok
}

// Observations returns every observation, sorted by ID.
func (g *Graph) Observations() []*Observation {
	out := make([]*Observation, 0, len(g.byID))
	for _, o := range g.byID {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Check re-verifies the whole graph against the contract: every observation is
// valid, every derived fact's inputs exist, and nothing claims more than the
// weakest evidence it rests on. Graph.Add already enforces this as evidence is
// added; Check is the independent second look the projection makes before it
// writes anything, so a bug in either place cannot produce an over-claiming report.
func (g *Graph) Check() error {
	for _, o := range g.Observations() {
		if err := Validate(*o); err != nil {
			return fmt.Errorf("observation %s: %w", o.ID, err)
		}
		if o.Origin != OriginDerived {
			continue
		}
		weakest := MinClass()
		for _, id := range o.BasedOn {
			in, ok := g.byID[id]
			if !ok {
				return fmt.Errorf("derived observation %s rests on %s, which is not in the graph", o.ID, id)
			}
			weakest = MinClass(weakest, ClassOf(in.Claim))
		}
		if ClassOf(o.Claim) > weakest {
			return fmt.Errorf("derived observation %s claims %s but rests only on %s evidence", o.ID, ClassOf(o.Claim), weakest)
		}
		for i, r := range o.Relations {
			if ClassOf(r.Claim) > weakest {
				return fmt.Errorf("derived observation %s relation %d claims %s but rests only on %s evidence", o.ID, i, ClassOf(r.Claim), weakest)
			}
		}
	}
	return nil
}
