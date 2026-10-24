package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// frozenVar is how a package variable a migration's Go step reads says it is frozen with that step.
var frozenVar = regexp.MustCompile(`V\d+$`)

// TestPostMigrationsUseOnlyFrozenCode enforces PRD-016 §5.2: a migration's Go step must do in 2028
// what it did on release day, or a database upgraded late ends up different from one upgraded on
// time. So the steps, and every function they reach in this package, may not:
//   - be methods (today's Store behaviour changes);
//   - use another package of this module (today's evaluation, server or model code changes);
//   - read a package variable unless its name ends in V<step> (frozen with the step, like
//     timestampColumnsV10).
//
// Constants and the standard library are allowed.
func TestPostMigrationsUseOnlyFrozenCode(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	funcs := map[string]*ast.FuncDecl{}
	fileOf := map[string]*ast.File{}
	vars := map[string]bool{}
	var post *ast.CompositeLit
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil {
					funcs[d.Name.Name] = d
					fileOf[d.Name.Name] = f
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				for _, sp := range d.Specs {
					vs := sp.(*ast.ValueSpec)
					for i, name := range vs.Names {
						vars[name.Name] = true
						if name.Name == "postMigrations" && i < len(vs.Values) {
							post, _ = vs.Values[i].(*ast.CompositeLit)
						}
					}
				}
			}
		}
	}
	if post == nil {
		t.Fatal("postMigrations not found")
	}

	var queue []string
	for _, el := range post.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			t.Fatalf("postMigrations entry is not key: value")
		}
		id, ok := kv.Value.(*ast.Ident)
		if !ok {
			t.Errorf("postMigrations[%s] must name a top-level function, not an expression", exprText(kv.Key))
			continue
		}
		queue = append(queue, id.Name)
	}

	seen := map[string]bool{}
	var problems []string
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		fd, ok := funcs[name]
		if !ok {
			problems = append(problems, name+": not a top-level function of this package (a method or a closure?)")
			continue
		}
		imports := map[string]string{}
		for _, im := range fileOf[name].Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			local := p[strings.LastIndex(p, "/")+1:]
			if im.Name != nil {
				local = im.Name.Name
			}
			imports[local] = p
		}
		local := localNames(fd)
		var visit func(n ast.Node) bool
		visit = func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SelectorExpr:
				if x, ok := n.X.(*ast.Ident); ok {
					if p, isPkg := imports[x.Name]; isPkg && !local[x.Name] {
						if strings.Contains(strings.SplitN(p, "/", 2)[0], ".") {
							problems = append(problems, name+": uses "+p+"."+n.Sel.Name+" (only the standard library is frozen)")
						}
						return false
					}
				}
				ast.Inspect(n.X, visit) // n.Sel is a field or method name, not a package-level name
				return false
			case *ast.Ident:
				if local[n.Name] {
					return true
				}
				if _, isFunc := funcs[n.Name]; isFunc {
					queue = append(queue, n.Name)
				}
				if vars[n.Name] && !frozenVar.MatchString(n.Name) {
					problems = append(problems, name+": reads package variable "+n.Name+" (copy it into a variable named …V<step> frozen with the migration)")
				}
			}
			return true
		}
		ast.Inspect(fd.Body, visit)
	}
	sort.Strings(problems)
	for _, p := range dedupe(problems) {
		t.Error(p)
	}
}

// localNames lists every name a function declares itself (parameters, results, := and var, range
// variables, closure parameters), so they are not mistaken for package-level names. Scoping is
// ignored: a local that shadows a package name hides it everywhere in the function, which only
// errs towards allowing.
func localNames(fd *ast.FuncDecl) map[string]bool {
	local := map[string]bool{}
	addFields := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, n := range f.Names {
				local[n.Name] = true
			}
		}
	}
	addFields(fd.Type.Params)
	addFields(fd.Type.Results)
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if n.Tok == token.DEFINE {
				for _, l := range n.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						local[id.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, id := range n.Names {
				local[id.Name] = true
			}
		case *ast.TypeSpec:
			local[n.Name.Name] = true
		case *ast.RangeStmt:
			if n.Tok == token.DEFINE {
				for _, e := range []ast.Expr{n.Key, n.Value} {
					if id, ok := e.(*ast.Ident); ok {
						local[id.Name] = true
					}
				}
			}
		case *ast.FuncLit:
			addFields(n.Type.Params)
			addFields(n.Type.Results)
		case *ast.KeyValueExpr:
			if id, ok := n.Key.(*ast.Ident); ok {
				local[id.Name] = true // a struct field name in a literal
			}
		}
		return true
	})
	return local
}

func dedupe(xs []string) []string {
	var out []string
	for i, x := range xs {
		if i == 0 || x != xs[i-1] {
			out = append(out, x)
		}
	}
	return out
}

func exprText(e ast.Expr) string {
	if b, ok := e.(*ast.BasicLit); ok {
		return b.Value
	}
	return "?"
}
