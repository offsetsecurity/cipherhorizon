// One certificate (PRD-003 REQ-CERT-8, PRD-012): the whole X.509 document, decoded from the DER a
// scan kept, in the order an engineer reads it, then every place it was seen. A certificate known
// only from a source that kept no DER shows the fields that source gave. Every value comes from the
// certificate, which an attacker may have chosen: it reaches the page as text only.
import { h, clear, fmtDate, fmtDay, daysUntil } from '../dom.js';
import { api } from '../api.js';
import { badge, skeleton, citations, crumbs, copyButton, button } from '../ui.js';
import { validFingerprint, systemHref, keyText, expiryBadge, classLabel, keyAssociation, validId } from '../estate-ui.js';

const cnOf = (dn) => { const m = /CN=([^,]+)/.exec(dn || ''); return m ? m[1] : (dn || ''); };
const words = (st) => (!st ? 'not rated' : st.status === 'rated' ? `${st.bits} bits` : st.status === 'disallowed' ? `${st.bits} bits, disallowed`
  : st.status === 'broken' ? 'broken' : 'not rated');
const pqBadge = (s) => (s === 'quantum-vulnerable' ? badge('✖ quantum-vulnerable', 'bad') : s === 'quantum-safe' ? badge('✔ quantum-safe', 'good')
  : h('span', { class: 'muted' }, 'no post-quantum verdict'));
const strengthOf = (st) => h('span', null, h('span', { class: st && st.status === 'broken' ? 'text-bad' : null }, words(st)),
  st && st.basis ? h('span', { class: 'cell-why' }, st.basis) : null);
const fact = (label, ...value) => h('div', null, h('dt', null, label), h('dd', null, ...value));
const list = (xs) => (xs && xs.length ? h('ul', { class: 'plainlist' }, xs.map((x) => h('li', null, x))) : h('span', { class: 'muted' }, 'none'));
const dnParts = (parts) => h('ul', { class: 'plainlist dn' }, (parts || []).map((p) => h('li', null, h('span', { class: 'muted' }, `${p.type} = `), p.value)));

function expiry(notAfter) {
  const d = daysUntil(notAfter);
  if (d === null) return null;
  return d < 0 ? badge('expired', 'bad') : d <= 30 ? badge(`${d} days left`, 'warn') : badge(`${d} days left`, 'good');
}

function kindWords(x) {
  if (!x.isCa) return 'End-entity (leaf) certificate';
  return x.selfSigned ? 'Root CA certificate (self-signed)' : 'Intermediate CA certificate';
}

/** The decoded document, section by section (ENH-003 §3.2). */
function x509Sections(x, fp, findings) {
  const out = [];
  const keyLine = [x.publicKey.algorithm, x.publicKey.curve || (x.publicKey.bits ? `${x.publicKey.bits}-bit` : '')].filter(Boolean).join(' ');
  out.push(h('section', { class: 'card x509-summary', 'aria-label': 'Summary' },
    h('p', { class: 'verdict-line' }, h('b', null, `For ${cnOf(x.subject) || 'an unnamed subject'}, issued by ${cnOf(x.issuer) || 'an unnamed issuer'}. `),
      `Valid until ${fmtDay(x.notAfter)} `, expiry(x.notAfter), '. ',
      `${keyLine} key, ${words(x.publicKey.strength)}`, x.publicKey.pqc === 'quantum-vulnerable' ? ', quantum-vulnerable' : x.publicKey.pqc === 'quantum-safe' ? ', quantum-safe' : '', '.',
      findings === null ? '' : findings ? ` ${findings} finding${findings === 1 ? '' : 's'} below.` : ' No finding applies.')));

  out.push(h('section', { class: 'card mt', 'aria-labelledby': 'x-id' }, h('h2', { id: 'x-id' }, 'Identity'),
    h('dl', { class: 'facts' },
      fact('Subject', dnParts(x.subjectParts)),
      fact('Issuer', dnParts(x.issuerParts)),
      fact('Type', kindWords(x)),
      fact('Serial number', h('span', { class: 'mono copyable' }, x.serial || 'none', x.serial ? copyButton(x.serial, 'serial number') : null)),
      fact('Version', `X.509 v${x.version}`),
      fact('Valid from', fmtDate(x.notBefore)),
      fact('Valid until', fmtDate(x.notAfter), ' ', expiry(x.notAfter)),
      fact('Lifetime', `${x.lifetimeDays} days`),
      x.validation ? fact('Validation type', x.validation) : null)));

  const n = x.names || {};
  out.push(h('section', { class: 'card mt', 'aria-labelledby': 'x-names' }, h('h2', { id: 'x-names' }, 'Names'),
    n.cnOnly ? h('div', { class: 'callout warn', role: 'note' }, 'The name is only in the subject’s common name, with no subject alternative name: modern clients reject it (RFC 9525).') : null,
    h('dl', { class: 'facts' },
      fact('DNS names', list(n.dns)),
      (n.ip || []).length ? fact('IP addresses', list(n.ip)) : null,
      (n.email || []).length ? fact('E-mail addresses', list(n.email)) : null,
      (n.uri || []).length ? fact('URIs', list(n.uri)) : null,
      (n.wildcards || []).length ? fact('Wildcards', list(n.wildcards)) : null)));

  const k = x.publicKey;
  out.push(h('section', { class: 'card mt', 'aria-labelledby': 'x-key' }, h('h2', { id: 'x-key' }, 'Public key'),
    h('dl', { class: 'facts' },
      fact('Algorithm', k.algorithm, h('span', { class: 'cell-why mono' }, k.oid)),
      k.curve ? fact('Curve', k.curve) : null,
      k.bits ? fact('Size', `${k.bits} bits`) : null,
      k.exponent ? fact('Public exponent', String(k.exponent)) : null,
      fact('Classical strength', strengthOf(k.strength)),
      fact('Post-quantum', pqBadge(k.pqc)),
      fact('Key fingerprint (SPKI SHA-256)', h('span', { class: 'mono copyable' }, k.spkiSha256, copyButton(k.spkiSha256, 'key fingerprint')),
        h('span', { class: 'cell-why' }, 'The same key keeps this fingerprint across certificates: use it to pin the key.')))));

  const s = x.signature;
  out.push(h('section', { class: 'card mt', 'aria-labelledby': 'x-sig' }, h('h2', { id: 'x-sig' }, 'Signature'),
    h('p', { class: 'hint' }, 'The issuer’s signature on this certificate. It is as strong as the weaker of its hash and the issuer’s key.'),
    h('dl', { class: 'facts' },
      fact('Algorithm', s.algorithm || 'not recorded', h('span', { class: 'cell-why mono' }, s.oid)),
      s.params ? fact('Parameters', s.params) : null,
      fact('Classical strength', strengthOf(s.strength)),
      fact('Post-quantum', pqBadge(s.pqc)))));

  const exts = x.extensions || [];
  const extValue = (e) => (e.values && e.values.length ? list(e.values)
    : h('span', { class: 'mono hexval' }, e.hex || '', e.cut ? h('span', { class: 'muted' }, ' … (first 512 bytes)') : null,
      h('span', { class: 'cell-why' }, 'Not decoded by this program: shown as it is.')));
  const extRow = (e) => h('tr', null,
    h('td', null, h('b', null, e.name), e.name !== e.oid ? h('span', { class: 'cell-why mono' }, e.oid) : null),
    h('td', null, e.critical ? badge('critical', 'warn') : h('span', { class: 'muted' }, 'no')),
    h('td', null, extValue(e)));
  const extTable = h('div', { class: 'tablewrap' }, h('table', { class: 'compact x509-ext' },
    h('thead', null, h('tr', null, ['Extension', 'Critical', 'Value'].map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, exts.map(extRow))));
  out.push(h('section', { class: 'card mt', 'aria-labelledby': 'x-ext' }, h('h2', { id: 'x-ext' }, `Extensions (${exts.length})`),
    exts.length ? extTable : h('p', { class: 'muted' }, 'This certificate carries no extensions (an X.509 v1 certificate).')));

  out.push(h('section', { class: 'card mt', 'aria-labelledby': 'x-fp' }, h('h2', { id: 'x-fp' }, 'Fingerprints'),
    h('dl', { class: 'facts' },
      fact('SHA-256', h('span', { class: 'mono copyable' }, x.sha256, copyButton(x.sha256, 'SHA-256 fingerprint'))),
      fact('SHA-1', h('span', { class: 'mono copyable' }, x.sha1, copyButton(x.sha1, 'SHA-1 fingerprint')),
        h('span', { class: 'cell-why' }, 'An identifier only, for searching CA portals and browsers. SHA-1 is broken for collisions: never decide trust by it.')))));

  const stem = (cnOf(x.subject) || fp.slice(0, 16)).replace(/[^a-z0-9._-]+/gi, '_');
  out.push(h('section', { class: 'card mt', 'aria-labelledby': 'x-raw' }, h('h2', { id: 'x-raw' }, 'The certificate (PEM)'),
    h('div', { class: 'row' },
      button('Copy PEM', async (e) => {
        try { await navigator.clipboard.writeText(x.pem); e.currentTarget.textContent = 'Copied'; } catch { /* clipboard refused */ }
      }, 'secondary'),
      button('Download .pem', () => api.downloadBlob(`${stem}.pem`, x.pem, 'application/x-pem-file'), 'secondary')),
    h('pre', { class: 'pem', tabindex: '0', 'aria-label': 'The certificate in PEM' }, x.pem),
    h('p', { class: 'hint' }, 'To read it with OpenSSL: ', h('code', null, `openssl x509 -in ${stem}.pem -text -noout`))));
  return out;
}

/** The fields an estate source gave, when no DER was kept (the page before PRD-012). */
function estateFacts(c) {
  return h('section', { class: 'card' },
    h('dl', { class: 'facts' },
      fact('Subject', c.subject || 'not recorded'),
      fact('Issuer', c.issuer || 'not recorded'),
      fact('Public key', keyText(c), c.keyBits ? null : h('div', { class: 'hint' }, c.keyLengthNote || '')),
      fact('Signature', c.signatureAlgorithm || 'not recorded'),
      fact('Valid until', c.notAfter ? fmtDate(c.notAfter) : 'not recorded', ' ', expiryBadge(c)),
      fact('Names', c.dnsNames || 'none recorded'),
      h('div', null, h('dt', null, 'Serial'), h('dd', { class: 'mono' }, c.serial || 'not recorded')),
      c.extKeyUsage ? fact('Extended key usage', c.extKeyUsage) : null,
      c.keyUsage ? fact('Key usage', c.keyUsage) : null,
      c.policyClass && c.policyClass !== 'unknown' ? fact('Validation type', c.policyClass) : null,
      c.lifetimeDays ? fact('Lifetime', `${c.lifetimeDays} days`) : null,
      c.wildcards ? fact('Wildcard names', c.wildcards) : null,
      c.cnOnly ? fact('Names', 'Common name only; no subject alternative name (modern clients will reject it)') : null,
      h('div', null, h('dt', null, 'SHA-256 fingerprint'), h('dd', { class: 'mono' }, c.fingerprint))));
}

export async function render(root, { args, query }) {
  const fp = String(args[0] || '').toLowerCase();
  if (!validFingerprint(fp)) { location.hash = '#/inventory/certificates'; return null; }
  const scan = query && query.get('scan');
  root.appendChild(skeleton(4));
  const orNull = (p) => p.catch((e) => { if (e && e.status === 404) return null; throw e; });
  const [d, xr] = await Promise.all([orNull(api.certificate(fp)), orNull(api.certificateX509(fp, /^\d+$/.test(scan || '') ? scan : ''))]);
  clear(root);
  if (!d && !xr) {
    root.appendChild(crumbs([['Inventory', '#/inventory'], ['Certificates', '#/inventory/certificates'], ['Not found']]));
    root.appendChild(h('div', { class: 'card' }, h('h1', null, 'This certificate is not known'), h('p', { class: 'muted' }, 'No scan, upload or import has seen a certificate with this fingerprint.')));
    return null;
  }
  const x = xr && xr.der ? xr.x509 : null;
  const c = d ? d.certificate : null;
  const title = (x && cnOf(x.subject)) || (c && c.name) || 'Certificate';
  root.appendChild(crumbs([['Inventory', '#/inventory'], ['Certificates', '#/inventory/certificates'], [title]]));
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, title), h('div', { class: 'sub' }, x ? kindWords(x) : `${c.role} certificate`))));
  const src = xr && xr.source;
  if (src && validId(src.assetId)) {
    root.appendChild(h('p', { class: 'served-by' }, 'Served by ', h('a', { href: `#/endpoints/${src.assetId}?tab=configuration` }, src.assetName || 'the endpoint'),
      `, certificate ${src.position + 1} of ${src.chainLength} in the chain${src.noSni ? ', to clients that send no server name' : ''}. `,
      h('a', { href: `#/endpoints/${src.assetId}?tab=configuration` }, 'Back to the chain')));
  }
  const findings = d ? (d.findingDetails || []).length : null;
  if (x) {
    root.append(...x509Sections(x, fp, findings));
  } else {
    root.appendChild(estateFacts(c));
    if (xr && xr.reason) root.appendChild(h('p', { class: 'hint mt' }, xr.reason));
  }
  if (!d) return null;

  root.appendChild(h('section', { class: 'card mt' }, h('h2', null, 'Findings'),
    d.findingDetails && d.findingDetails.length
      ? d.findingDetails.map((f) => h('div', { class: 'finding' },
        h('div', { class: 'finding-head' }, badge(f.severity, f.severity === 'critical' || f.severity === 'high' ? 'bad' : 'warn'), ' ', h('b', null, f.title)),
        h('p', null, f.detail || ''), f.remediation ? h('p', { class: 'hint' }, f.remediation) : null, citations(f.citations)))
      : h('p', { class: 'hint' }, 'No finding applies to this certificate on the current evidence.')));

  root.appendChild(h('section', { class: 'card mt' }, h('h2', null, 'Where it was seen'),
    h('p', { class: 'hint' }, 'Each row is one observation: who made it, by what method, and how much that method can be trusted. “Key” says only what the sensor checked: it reads a property and never opens a key.'),
    h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
      h('thead', null, h('tr', null, ['System', 'Source', 'How', 'Position or location', 'Key', 'Seen'].map((x2) => h('th', { scope: 'col' }, x2)))),
      h('tbody', null, (d.places || []).map((p) => h('tr', null,
        h('td', { class: 'namecell' }, validId(p.systemId) ? h('a', { href: systemHref(p.systemId) }, p.systemName) : p.systemName),
        h('td', null, classLabel(p.sourceClass), h('div', { class: 'muted small' }, p.stream)),
        h('td', null, p.method, h('div', { class: 'muted small' }, `${p.rung}; ${p.methodQuality}`)),
        h('td', null, p.position || p.location || h('span', { class: 'muted' }, '·')),
        h('td', null, p.privateKey ? keyAssociation(p.privateKey) : h('span', { class: 'muted' }, 'not applicable')),
        h('td', { class: 'muted' }, fmtDate(p.observedAt)))))))));
  return null;
}
