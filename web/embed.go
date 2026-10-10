// Package web holds the embedded user interface: plain HTML, CSS and ES modules,
// with no build step and no external requests.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var content embed.FS

// Handler serves the UI from the binary.
func Handler() http.Handler {
	sub, err := fs.Sub(content, "static")
	if err != nil {
		panic(err) // the embed directive guarantees the directory exists
	}
	return http.FileServer(http.FS(sub))
}
