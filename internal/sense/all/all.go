// Package all links in every built-in sensor. Import it for its side effect:
//
//	import _ "github.com/example/cipherhorizon/internal/sense/all"
package all

import (
	_ "github.com/example/cipherhorizon/internal/sense/certfiles" // registers "cert-files"
	_ "github.com/example/cipherhorizon/internal/sense/debian"    // registers "apt"
	_ "github.com/example/cipherhorizon/internal/sense/pefiles"   // registers "pe-files"
	_ "github.com/example/cipherhorizon/internal/sense/wincerts"  // registers "windows-certs"
	_ "github.com/example/cipherhorizon/internal/sense/wincng"    // registers "windows-cng"
)
