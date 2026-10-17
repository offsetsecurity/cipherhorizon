package archtest

import (
	"os"
	"strings"
	"testing"
)

// PRD-007 REQ-DP-3: the systemd unit runs the server unprivileged and sandboxed.
func TestSystemdUnitIsSandboxed(t *testing.T) {
	b, err := os.ReadFile("../../deploy/cipherhorizon.service")
	if err != nil {
		t.Fatal(err)
	}
	unit := map[string][]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			unit[k] = append(unit[k], v)
		}
	}
	for key, want := range map[string]string{
		"DynamicUser": "yes", "NoNewPrivileges": "yes", "CapabilityBoundingSet": "", "AmbientCapabilities": "",
		"ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes", "PrivateDevices": "yes",
		"ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectControlGroups": "yes",
		"RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX", "RestrictNamespaces": "yes", "RestrictSUIDSGID": "yes",
		"MemoryDenyWriteExecute": "yes", "LockPersonality": "yes", "SystemCallArchitectures": "native",
		"StateDirectory": "cipherhorizon", "StateDirectoryMode": "0700", "UMask": "0077",
	} {
		got := unit[key]
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	exec := strings.Join(unit["ExecStart"], " ")
	// The host alone (PRD-009 REQ-PORT-4): the port is 8080 unless CIPHERHORIZON_OPTS says --port.
	if !strings.Contains(exec, "--addr 127.0.0.1 ") || !strings.Contains(exec, "/var/lib/cipherhorizon/") || strings.Contains(exec, "--no-login") {
		t.Errorf("ExecStart = %q: it must listen on loopback, keep its database in the state directory and require sign-in", exec)
	}
	if len(unit["User"]) > 0 {
		t.Error("a fixed User= defeats DynamicUser")
	}
}

// REQ-DP-2 (audit L-13): both compose files run the container read-only, without capabilities and
// without the means to gain privileges; only Caddy is published in the Caddy variant.
func TestComposeFilesAreHardened(t *testing.T) {
	for _, f := range []string{"../../docker-compose.yml", "../../deploy/compose-caddy.yml"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		start := strings.Index(s, "  cipherhorizon:")
		if start < 0 {
			t.Fatalf("%s has no cipherhorizon service", f)
		}
		svc := s[start:]
		if i := strings.Index(svc[1:], "\n  caddy:"); i > 0 {
			svc = svc[:i]
		}
		if i := strings.Index(svc, "\nvolumes:"); i > 0 {
			svc = svc[:i]
		}
		if i := strings.Index(svc, "\nnetworks:"); i > 0 {
			svc = svc[:i]
		}
		for _, want := range []string{"read_only: true", "no-new-privileges:true", "pids_limit:", "mem_limit:", "/tmp:"} {
			if !strings.Contains(svc, want) {
				t.Errorf("%s: the cipherhorizon service lacks %q", f, want)
			}
		}
		if !strings.Contains(svc, "cap_drop:\n      - ALL") && !strings.Contains(svc, "cap_drop: [ALL]") {
			t.Errorf("%s: capabilities are not all dropped", f)
		}
		if strings.Contains(f, "caddy") {
			if strings.Contains(svc, "ports:") {
				t.Errorf("%s: cipherhorizon is published on a host port; only Caddy should be", f)
			}
			if !strings.Contains(svc, "--trusted-proxy") {
				t.Errorf("%s: without --trusted-proxy every client looks like Caddy", f)
			}
			if !strings.Contains(svc, `"--sign-in", "on"`) {
				t.Errorf("%s: a server reachable from the internet must require sign-in", f)
			}
		} else if !strings.Contains(svc, `"127.0.0.1:8080:8080"`) {
			t.Errorf("%s: the port must be published on loopback only", f)
		}
	}
}
