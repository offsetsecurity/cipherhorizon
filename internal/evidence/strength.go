package evidence

// Class is how strong a statement is. A relationship, and a path made of
// relationships, has the class of its weakest link, and the words a report may
// use follow the class.
//
//	E0 existence  <  E1 reachable  <  E2 loaded  <  E3 exercised
type Class int

// The classes.
const (
	E0Existence Class = iota
	E1Reachable
	E2Loaded
	E3Exercised
)

// String is the short name used in messages.
func (c Class) String() string {
	switch c {
	case E0Existence:
		return "E0 existence"
	case E1Reachable:
		return "E1 reachable"
	case E2Loaded:
		return "E2 loaded"
	case E3Exercised:
		return "E3 exercised"
	}
	return "unknown class"
}

// Wording is what a report may say at this class, and no more.
func (c Class) Wording() string {
	switch c {
	case E0Existence:
		return "is present / can perform (mapped or probed)"
	case E1Reachable:
		return "could use / is configured to permit"
	case E2Loaded:
		return "has loaded"
	case E3Exercised:
		return "was observed performing"
	}
	return ""
}

// ClassOf is the strength class of a claim. Policy is a modifier, not a link in a
// chain (it changes what a path means without making it stronger), so it is
// existence-class here and is applied separately.
func ClassOf(c Claim) Class {
	switch c.Rung {
	case RungBound:
		return E1Reachable
	case RungLoaded:
		return E2Loaded
	case RungExercised:
		return E3Exercised
	}
	return E0Existence
}

// MinClass is the weakest of the given classes; the empty list is the strongest
// (nothing weakens it).
func MinClass(cs ...Class) Class {
	if len(cs) == 0 {
		return E3Exercised
	}
	min := cs[0]
	for _, c := range cs[1:] {
		if c < min {
			min = c
		}
	}
	return min
}
