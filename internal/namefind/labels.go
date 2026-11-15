package namefind

import (
	_ "embed"
	"strconv"
	"strings"
	"sync"
)

//go:embed labels.txt
var labelsText string

// envPrefixes and envStems make names such as "dev-api" and "uat-portal".
var (
	envPrefixes = []string{"dev", "test", "qa", "uat", "stg", "staging", "preprod", "prod", "demo", "sandbox"}
	envStems    = []string{"api", "app", "web", "www", "portal", "admin", "auth", "sso", "login", "mail", "db", "vpn", "cdn", "shop", "pay", "secure", "mobile", "services"}
	numbered    = []string{"www", "web", "app", "api", "mail", "mx", "ns", "vpn", "srv", "server", "host", "node", "db", "lb", "proxy", "gw", "fw", "cdn", "portal", "ftp"}
)

var labelsOnce = sync.OnceValue(func() []string {
	seen := map[string]bool{}
	var out []string
	add := func(l string) {
		if l != "" && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	for _, line := range strings.Split(labelsText, "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		for _, l := range strings.Fields(line) {
			add(l)
		}
	}
	for _, stem := range numbered {
		for i := 1; i <= 6; i++ {
			add(stem + strconv.Itoa(i))
			add(stem + "0" + strconv.Itoa(i))
			add(stem + "-" + strconv.Itoa(i))
		}
	}
	for _, p := range envPrefixes {
		for _, s := range envStems {
			add(p + "-" + s)
			add(s + "-" + p)
			add(p + s)
			add(s + "." + p) // api.dev.example.com
		}
	}
	return out
})

// Labels is the built-in list of labels tried by the word-list source.
func Labels() []string { return labelsOnce() }
