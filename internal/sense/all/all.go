// Package all links in every built-in sensor. Import it for its side effect:
//
//	import _ "github.com/offsetsecurity/cipherhorizon/internal/sense/all"
package all

import (
	_ "github.com/offsetsecurity/cipherhorizon/internal/sense/certfiles" // registers "cert-files"
	_ "github.com/offsetsecurity/cipherhorizon/internal/sense/debian"    // registers "apt"
	_ "github.com/offsetsecurity/cipherhorizon/internal/sense/pefiles"   // registers "pe-files"
	_ "github.com/offsetsecurity/cipherhorizon/internal/sense/wincerts"  // registers "windows-certs"
	_ "github.com/offsetsecurity/cipherhorizon/internal/sense/wincng"    // registers "windows-cng"
)
