// Package connector is the registry of integrations (PRD-023 M3): what each one is for, what it can
// do, how it authenticates, what it needs configured and what it cannot do. A connector is listed as
// available only when it is implemented and tested in this program; everything else is listed as
// planned, with what it would need, so nobody mistakes the roadmap for a feature.
//
// The rules every connector follows (ADR-0023):
//   - it acts only on a transition a person made on approved work, never on its own schedule;
//   - it cannot enter a verified stage: verification is the product's own scan;
//   - credentials are references (an environment variable, a file), never values in the database,
//     and are never returned by the API;
//   - every call is recorded with its outcome; a call has a timeout and bounded retries;
//   - outbound connections go through the same address guard as scans, without the scan scope.
package connector

// Categories.
const (
	Discovery    = "discovery"    // imports cryptographic assets and certificates
	Issuer       = "issuer"       // requests, renews and revokes certificates
	Deployment   = "deployment"   // installs certificates and activates configuration
	Verification = "verification" // checks what is actually deployed
	Workflow     = "workflow"     // change management and approvals in another system
	Notification = "notification" // tells people
)

// Status of a connector in this build.
const (
	Available = "available" // implemented and tested here
	Planned   = "planned"   // evaluated, not built
)

// Descriptor says what a connector is and does.
type Descriptor struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Categories   []string `json:"categories"`
	Status       string   `json:"status"`
	Summary      string   `json:"summary"`
	Capabilities []string `json:"capabilities"`
	Auth         []string `json:"auth"`
	Config       []string `json:"config"`
	Limits       []string `json:"limits"`
	Licence      string   `json:"licence,omitempty"`
	Docs         string   `json:"docs,omitempty"`
}

// Registry lists every connector, available ones first.
func Registry() []Descriptor {
	return []Descriptor{
		{
			ID: "scanner", Name: "CipherHorizon scanner and collectors", Categories: []string{Verification, Discovery}, Status: Available,
			Summary:      "The product's own TLS and SSH scans and host inventories. The only source that can mark work verified.",
			Capabilities: []string{"verify a finding is gone", "verify a certificate was replaced on every endpoint that served it", "verify a readiness level is reached", "discover endpoints from a domain"},
			Auth:         []string{"none: it connects to the endpoints you add, within --scan-allow"},
			Config:       []string{"endpoints and machines", "--scan-allow"},
			Limits:       []string{"sees what a client sees: a library's capabilities inside an application are not observable from the network"},
			Docs:         "docs/work.md",
		},
		{
			ID: "webhook", Name: "Webhook", Categories: []string{Notification, Workflow}, Status: Available,
			Summary:      "Sends each lifecycle event once, as JSON (signed with HMAC-SHA256 when a secret is set) or as a chat message Slack and Microsoft Teams incoming webhooks accept.",
			Capabilities: []string{"work overdue or due soon", "approval needed", "exception ended", "verified change no longer holds", "certificate expiring or expired", "certificate changed without planned work"},
			Auth:         []string{"HMAC-SHA256 signature over the body, secret read from an environment variable named in Settings"},
			Config:       []string{"webhook address (http or https)", "format: json or chat", "secret environment variable (optional)", "which events"},
			Limits:       []string{"one destination", "Teams Workflows webhooks that need an Adaptive Card are not supported", "five delivery attempts per event, then it is marked failed"},
			Docs:         "docs/work.md#the-lifecycle-monitor-and-notifications",
		},
		{
			ID: "acme", Name: "ACME (RFC 8555)", Categories: []string{Issuer}, Status: Planned, Licence: "BSD-3-Clause (golang.org/x/crypto/acme, already a dependency)",
			Summary:      "Order and renew certificates from any ACME CA: Let's Encrypt, Smallstep step-ca, ZeroSSL, a cloud CA's ACME endpoint.",
			Capabilities: []string{"order", "renew", "revoke"},
			Auth:         []string{"ACME account key (generated and kept at the approved destination)", "external account binding where the CA requires it"},
			Config:       []string{"directory URL", "challenge type and its credentials, by reference", "where the new key and certificate are written"},
			Limits:       []string{"planned for milestone 3; tested against step-ca in a container before it is offered"},
		},
		{
			ID: "step-ca", Name: "Smallstep step-ca", Categories: []string{Issuer}, Status: Planned, Licence: "Apache-2.0",
			Summary:      "Internal CA. Reached through its ACME provisioner first; its own API (JWK/OIDC provisioners) later.",
			Capabilities: []string{"order", "renew", "revoke"}, Auth: []string{"ACME", "JWK or OIDC provisioner token"},
			Config: []string{"CA URL and root fingerprint", "provisioner"}, Limits: []string{"planned; through the ACME connector"},
		},
		{
			ID: "cert-manager", Name: "cert-manager (Kubernetes)", Categories: []string{Discovery, Issuer}, Status: Planned, Licence: "Apache-2.0",
			Summary:      "Read Certificate resources as inventory; ask cert-manager to reissue one.",
			Capabilities: []string{"discover", "renew"}, Auth: []string{"service-account token with read on certificates, patch on certificates/status"},
			Config: []string{"API server URL and CA", "namespaces"}, Limits: []string{"planned; the Kubernetes client library is large, so plain HTTP is preferred"},
		},
		{
			ID: "ansible", Name: "Ansible", Categories: []string{Deployment}, Status: Planned, Licence: "GPL-3.0 (run as a separate program, never linked)",
			Summary:      "Run a playbook you own to deploy a renewed certificate or a configuration change.",
			Capabilities: []string{"deploy"}, Auth: []string{"whatever your inventory uses; never stored here"},
			Config: []string{"playbook path", "inventory"}, Limits: []string{"needs ADR-0004 amended: library code starts no program today"},
		},
		{
			ID: "openbao", Name: "OpenBao PKI", Categories: []string{Issuer}, Status: Planned, Licence: "MPL-2.0",
			Summary: "Issue from an OpenBao PKI secrets engine.", Capabilities: []string{"issue", "revoke"},
			Auth: []string{"AppRole or token, by reference"}, Config: []string{"address", "mount and role"}, Limits: []string{"planned"},
		},
		{
			ID: "aws-acm", Name: "AWS Certificate Manager", Categories: []string{Discovery, Issuer}, Status: Planned,
			Summary: "List certificates in ACM as inventory; renew private certificates.", Capabilities: []string{"discover", "renew (private CA)"},
			Auth: []string{"IAM role (SigV4)"}, Config: []string{"regions"}, Limits: []string{"planned; read-only first"},
		},
		{
			ID: "azure-key-vault", Name: "Azure Key Vault", Categories: []string{Discovery, Issuer}, Status: Planned,
			Summary: "List certificates in a vault; trigger renewal where the vault manages it.", Capabilities: []string{"discover", "renew"},
			Auth: []string{"Entra ID application, by reference"}, Config: []string{"vault URL"}, Limits: []string{"planned; read-only first"},
		},
		{
			ID: "email", Name: "E-mail (SMTP)", Categories: []string{Notification}, Status: Planned,
			Summary: "Send lifecycle events by e-mail through your relay.", Capabilities: []string{"notify"},
			Auth: []string{"SMTP credentials, by reference"}, Config: []string{"relay", "recipients"}, Limits: []string{"planned; use the webhook with your mail or chat bridge meanwhile"},
		},
	}
}
