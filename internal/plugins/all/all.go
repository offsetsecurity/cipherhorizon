// Package all links in every built-in plugin. The composition root imports it
// for its side effect: each plugin registers itself from its init function.
package all

import (
	_ "github.com/example/cbom-scan/internal/plugins/apt" // registers "apt"
)
