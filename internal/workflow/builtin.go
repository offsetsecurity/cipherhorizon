package workflow

import (
	"embed"
	"fmt"
	"path"
	"sort"
	"sync"
)

//go:embed templates/*.json
var builtinFS embed.FS

var (
	builtinOnce sync.Once
	builtins    []*Template
	builtinErr  error
)

// BuiltIn lists the built-in templates, sorted by id. It panics if one is invalid, which a test rules out.
func BuiltIn() []*Template {
	builtinOnce.Do(func() {
		entries, err := builtinFS.ReadDir("templates")
		if err != nil {
			builtinErr = err
			return
		}
		for _, e := range entries {
			b, err := builtinFS.ReadFile(path.Join("templates", e.Name()))
			if err != nil {
				builtinErr = err
				return
			}
			t, err := Parse(b)
			if err != nil {
				builtinErr = fmt.Errorf("%s: %w", e.Name(), err)
				return
			}
			if t.ID+".json" != e.Name() {
				builtinErr = fmt.Errorf("%s holds template %q", e.Name(), t.ID)
				return
			}
			builtins = append(builtins, t)
		}
		sort.Slice(builtins, func(i, j int) bool { return builtins[i].ID < builtins[j].ID })
	})
	if builtinErr != nil {
		panic("workflow: built-in template: " + builtinErr.Error())
	}
	return builtins
}

// IsBuiltIn says whether an id belongs to a built-in template (which a custom template may not replace).
func IsBuiltIn(id string) bool {
	_, ok := BuiltInByID(id)
	return ok
}

// BuiltInByID returns a built-in template.
func BuiltInByID(id string) (*Template, bool) {
	for _, t := range BuiltIn() {
		if t.ID == id {
			return t, true
		}
	}
	return nil, false
}
