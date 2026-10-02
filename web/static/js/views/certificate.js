// One certificate: what it is, every place it was seen and how (PRD-003 REQ-CERT-8). Only public
// details exist in the estate; the wording about keys says what the sensors actually check.
import { h, clear, fmtDate } from '../dom.js';
import { api } from '../api.js';
import { badge, skeleton, citations } from '../ui.js';
import { validFingerprint, systemHref, keyText, expiryBadge, classLabel, keyAssociation, validId } from '../estate-ui.js';

export async function render(root, { args }) {
  const fp = String(args[0] || '').toLowerCase();
  if (!validFingerprint(fp)) { location.hash = '#/certificates'; return null; }
  root.appendChild(skeleton(4));
  const d = await api.certificate(fp);
  clear(root);
  const c = d.certificate;
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, c.name || 'Certificate'), h('div', { class: 'sub' }, `${c.role} certificate`)),
    h('div', { class: 'row' }, h('a', { class: 'btn btn-secondary', href: '#/certificates' }, 'All certificates'))));
  root.appendChild(h('section', { class: 'card' },
    h('dl', { class: 'facts' },
      h('div', null, h('dt', null, 'Subject'), h('dd', null, c.subject || 'not recorded')),
      h('div', null, h('dt', null, 'Issuer'), h('dd', null, c.issuer || 'not recorded')),
      h('div', null, h('dt', null, 'Public key'), h('dd', null, keyText(c), c.keyBits ? null : h('div', { class: 'hint' }, c.keyLengthNote || ''))),
      h('div', null, h('dt', null, 'Signature'), h('dd', null, c.signatureAlgorithm || 'not recorded')),
      h('div', null, h('dt', null, 'Valid until'), h('dd', null, c.notAfter ? fmtDate(c.notAfter) : 'not recorded', ' ', expiryBadge(c))),
      h('div', null, h('dt', null, 'Names'), h('dd', null, c.dnsNames || 'none recorded')),
      h('div', null, h('dt', null, 'Serial'), h('dd', { class: 'mono' }, c.serial || 'not recorded')),
      c.extKeyUsage ? h('div', null, h('dt', null, 'Extended key usage'), h('dd', null, c.extKeyUsage)) : null,
      c.keyUsage ? h('div', null, h('dt', null, 'Key usage'), h('dd', null, c.keyUsage)) : null,
      c.policyClass && c.policyClass !== 'unknown' ? h('div', null, h('dt', null, 'Validation type'), h('dd', null, c.policyClass)) : null,
      c.lifetimeDays ? h('div', null, h('dt', null, 'Lifetime'), h('dd', null, `${c.lifetimeDays} days`)) : null,
      c.wildcards ? h('div', null, h('dt', null, 'Wildcard names'), h('dd', null, c.wildcards)) : null,
      c.cnOnly ? h('div', null, h('dt', null, 'Names'), h('dd', null, 'Common name only; no subject alternative name (modern clients will reject it)')) : null,
      h('div', null, h('dt', null, 'SHA-256 fingerprint'), h('dd', { class: 'mono' }, c.fingerprint)))));

  root.appendChild(h('section', { class: 'card mt' }, h('h2', null, 'Findings'),
    d.findingDetails && d.findingDetails.length
      ? d.findingDetails.map((f) => h('div', { class: 'finding' },
        h('div', { class: 'finding-head' }, badge(f.severity, f.severity === 'critical' || f.severity === 'high' ? 'bad' : 'warn'), ' ', h('b', null, f.title)),
        h('p', null, f.detail || ''), f.remediation ? h('p', { class: 'hint' }, f.remediation) : null, citations(f.citations)))
      : h('p', { class: 'hint' }, 'No finding applies to this certificate on the current evidence.')));

  root.appendChild(h('section', { class: 'card mt' }, h('h2', null, 'Where it was seen'),
    h('p', { class: 'hint' }, 'Each row is one observation: who made it, by what method, and how much that method can be trusted. “Key” says only what the sensor checked: it reads a property and never opens a key.'),
    h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
      h('thead', null, h('tr', null, ['System', 'Source', 'How', 'Position or location', 'Key', 'Seen'].map((x) => h('th', { scope: 'col' }, x)))),
      h('tbody', null, (d.places || []).map((p) => h('tr', null,
        h('td', { class: 'namecell' }, validId(p.systemId) ? h('a', { href: systemHref(p.systemId) }, p.systemName) : p.systemName),
        h('td', null, classLabel(p.sourceClass), h('div', { class: 'muted small' }, p.stream)),
        h('td', null, p.method, h('div', { class: 'muted small' }, `${p.rung}; ${p.methodQuality}`)),
        h('td', null, p.position || p.location || h('span', { class: 'muted' }, '–')),
        h('td', null, p.privateKey ? keyAssociation(p.privateKey) : h('span', { class: 'muted' }, 'not applicable')),
        h('td', { class: 'muted' }, fmtDate(p.observedAt)))))))));
  return null;
}
