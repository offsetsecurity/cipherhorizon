// One certificate (PRD-003 REQ-CERT-8, PRD-012, UX-DESIGN-011 §3.3): the whole X.509 document,
// decoded from the DER a scan kept, drawn as instruments in the order an engineer reads it: where it
// sits in its chain, who it is for, how long it lasts, how strong its key and signature are, what it
// is for, every extension, its identifiers and the PEM. A certificate known only from a source that
// kept no DER shows the fields that source gave. Every value comes from the certificate, which an
// attacker may have chosen: it reaches the page as text only.
import { h, clear, fmtDate, fmtDay, daysUntil } from '../dom.js';
import { api } from '../api.js';
import { badge, skeleton, citations, crumbs, copyButton, button } from '../ui.js';
import { validFingerprint, systemHref, keyText, expiryBadge, classLabel, keyAssociation, validId } from '../estate-ui.js';
import { bitsBar, pqGlyph, lifetimeBar } from '../viz.js';

const cnOf = (dn) => { const m = /CN=([^,]+)/.exec(dn || ''); return m ? m[1] : (dn || ''); };
const orgOf = (parts) => ((parts || []).find((p) => p.type === 'O') || {}).value || '';
const pqWord = (s) => (s === 'quantum-vulnerable' ? 'Quantum-vulnerable' : s === 'quantum-safe' ? 'Quantum-safe' : 'No post-quantum verdict');
const certHref = (sha256, scanId) => `#/certificates/${sha256}${scanId ? `?scan=${scanId}` : ''}`;
const card = (id, title, aside, ...body) => h('section', { class: 'card xcard', 'aria-labelledby': id },
  h('div', { class: 'cfg-head' }, h('h2', { id }, title), aside || null), ...body);

function kindWords(x) {
  if (!x.isCa) return 'End-entity';
  return x.selfSigned ? 'Root CA' : 'Intermediate CA';
}

/** The chain this certificate was served in, from the scan's report: each card links to its page. */
async function chainRibbon(fp, src) {
  if (!src || !src.scanId) return null;
  let rep;
  try { rep = await api.report(src.scanId); } catch { return null; }
  const cr = (rep.certificates || []).find((c) => (c.chain || []).some((x) => x.sha256 === fp));
  if (!cr) return null;
  const cards = cr.chain.map((c, i) => {
    const here = c.sha256 === fp;
    const role = i === 0 ? 'Leaf' : c.selfSigned ? 'Root' : 'Intermediate';
    return h('li', { class: `chaincard${here ? ' is-here' : ''}` }, h('span', { class: 'cc-role' }, here ? `${role} · this certificate` : role),
      here ? h('span', { class: 'servedcn' }, cnOf(c.subject)) : h('a', { class: 'servedcn', href: certHref(c.sha256, src.scanId) }, cnOf(c.subject)),
      h('span', { class: 'cc-foot' }, `${c.publicKey ? `${c.publicKey.algorithm}${c.publicKey.curve ? ` ${c.publicKey.curve}` : c.publicKey.bits ? `-${c.publicKey.bits}` : ''}` : ''} · until ${fmtDay(c.notAfter)}`));
  });
  const top = cr.chain[cr.chain.length - 1];
  if (top && !top.selfSigned) {
    cards.push(h('li', { class: 'chaincard is-missing' }, h('span', { class: 'cc-role' }, 'Issuer, not sent'), h('span', { class: 'servedcn' }, cnOf(top.issuer)),
      h('span', { class: 'cc-foot' }, 'A client finds it in its trust store, or the chain is incomplete')));
  }
  return h('nav', { class: 'xchain', 'aria-label': `Chain as served by ${src.assetName || 'the endpoint'}` },
    h('ol', { class: 'chainribbon' }, cards),
    h('p', { class: 'hint' }, 'Served by ', validId(src.assetId) ? h('a', { href: `#/endpoints/${src.assetId}?tab=configuration` }, src.assetName || 'the endpoint') : (src.assetName || 'the endpoint'),
      `, certificate ${src.position + 1} of ${src.chainLength}${src.noSni ? ', to clients that send no server name' : ''}. `,
      validId(src.assetId) ? h('a', { href: `#/endpoints/${src.assetId}?tab=configuration`, class: 'served-by' }, 'Back to the chain') : null));
}

function meter(id, title, alg, detail, st, pq) {
  return card(id, title, h('span', { class: `pqword pq-${pq || 'na'}` }, pqGlyph(pq), pqWord(pq)),
    h('div', { class: 'meter-alg' }, h('code', null, alg || 'unknown'), detail ? h('span', { class: 'muted' }, detail) : null),
    bitsBar(st, { name: title }),
    st && st.basis ? h('p', { class: 'hint meter-basis' }, st.basis) : null);
}

const USAGE_EXT = { '2.5.29.15': 'key usage', '2.5.29.37': 'extended key usage', '2.5.29.19': 'basic constraints', '1.3.6.1.5.5.7.1.24': 'TLS feature' };
const USAGE_WORD = { digitalSignature: 'Digital signature', keyEncipherment: 'Key encipherment', keyAgreement: 'Key agreement', keyCertSign: 'Signs certificates',
  cRLSign: 'Signs CRLs', contentCommitment: 'Content commitment', dataEncipherment: 'Data encipherment', serverAuth: 'TLS server', clientAuth: 'TLS client',
  codeSigning: 'Code signing', emailProtection: 'E-mail protection', OCSPSigning: 'OCSP signing', timeStamping: 'Time stamping' };

// The two ends of the lifetime, and "today" where today falls on the bar (not in the middle).
function validityDates(x) {
  const from = Date.parse(x.notBefore), to = Date.parse(x.notAfter), now = Date.now();
  const today = h('span', { class: 'xvalid-today' }, 'today');
  const at = Number.isFinite(from) && Number.isFinite(to) && to > from ? Math.max(0, Math.min(1, (now - from) / (to - from))) : null;
  if (at !== null) today.style.left = `${at * 100}%`;
  return h('div', { class: 'xvalid-dates' }, h('span', null, fmtDate(x.notBefore)), at !== null && at > 0.12 && at < 0.88 ? today : null, h('span', null, fmtDate(x.notAfter)));
}

// RFC 8813 §3: an elliptic-curve key cannot encipher keys; a certificate that says it may was misissued.
const EC_KEY = /^(ECDSA|EC|Ed25519|Ed448|X25519|X448)$/i;

function x509Sections(x, fp, findings) {
  const out = [];
  const left = daysUntil(x.notAfter);
  out.push(h('section', { class: 'card xcard', 'aria-labelledby': 'x-valid' },
    h('div', { class: 'cfg-head' }, h('h2', { id: 'x-valid' }, 'Validity'),
      h('span', { class: 'xvalid-left' }, left === null ? '' : left < 0 ? h('b', { class: 'text-bad' }, `Expired ${-left} days ago`)
        : [h('b', { class: left <= 30 ? 'lt-warn-text' : 'lt-good-text' }, String(left)), ` days left of ${x.lifetimeDays}`])),
    lifetimeBar(x.notBefore, x.notAfter),
    validityDates(x)));

  const k = x.publicKey;
  out.push(h('div', { class: 'xmeters' },
    meter('x-key', 'Public key', `${k.algorithm}${k.curve ? ` ${k.curve}` : ''}`, [k.bits ? `${k.bits}-bit` : '', k.exponent ? `e = ${k.exponent}` : ''].filter(Boolean).join(' · '), k.strength, k.pqc),
    meter('x-sig', 'Issuer’s signature', x.signature.algorithm, x.signature.params || '', x.signature.strength, x.signature.pqc)));

  const n = x.names || {};
  const nameChips = [
    ...(n.dns || []).map((d) => h('span', { class: `nmchip ${d.startsWith('*.') ? 'nm-wild' : 'nm-dns'}`, title: d.startsWith('*.') ? 'Wildcard DNS name' : 'DNS name' }, d)),
    ...(n.ip || []).map((d) => h('span', { class: 'nmchip', title: 'IP address' }, d)),
    ...(n.email || []).map((d) => h('span', { class: 'nmchip', title: 'E-mail address' }, d)),
    ...(n.uri || []).map((d) => h('span', { class: 'nmchip', title: 'URI' }, d)),
  ];
  const usage = [];
  for (const e of x.extensions || []) {
    if (!USAGE_EXT[e.oid]) continue;
    for (const v of e.values || []) {
      const odd = (v === 'keyEncipherment' || v === 'dataEncipherment') && EC_KEY.test(x.publicKey.algorithm || '');
      usage.push(h('span', { class: `usechip${odd ? ' usechip-odd' : ''}`, title: odd ? 'An elliptic-curve key cannot encipher: RFC 8813 says a CA must not set this for it' : `${e.name}${e.critical ? ', critical' : ''}` },
        odd ? h('span', { 'aria-hidden': 'true' }, '!') : null, USAGE_WORD[v] || v, e.critical ? h('span', { class: 'crit' }, 'critical') : null, odd ? h('span', { class: 'usechip-why' }, 'not for an EC key') : null));
    }
  }
  out.push(h('section', { class: 'card xcard xnames', 'aria-label': 'Names and uses' },
    h('div', null, h('h2', null, 'Names it is valid for'),
      n.cnOnly ? h('p', { class: 'callout warn' }, 'Only a common name and no subject alternative name: modern clients reject it (RFC 9525).') : null,
      h('div', { class: 'chipwrap' }, nameChips.length ? nameChips : h('span', { class: 'muted' }, 'none'))),
    h('div', null, h('h2', null, 'What it may be used for'), h('div', { class: 'chipwrap' }, usage.length ? usage : h('span', { class: 'muted' }, 'no usage extensions: any use')))));

  const exts = x.extensions || [];
  const crit = exts.filter((e) => e.critical).length;
  out.push(card('x-ext', 'Every extension', h('span', { class: 'cfg-aside' }, `${exts.length}${crit ? ` · ${crit} critical` : ''}`),
    exts.length ? h('dl', { class: 'specsheet' }, exts.flatMap((e) => [
      h('dt', null, h('span', null, e.name), e.name !== e.oid ? h('span', { class: 'spec-oid' }, e.oid) : h('span', { class: 'spec-oid' }, 'not decoded: shown as it is')),
      h('dd', null, e.critical ? h('span', { class: 'crit' }, 'critical') : null,
        (e.values || []).length ? (e.values || []).map((v) => h('span', { class: 'specval' }, v))
          : h('span', { class: 'specval mono hexval' }, e.hex || '', e.cut ? ' … (first 512 bytes)' : '')),
    ])) : h('p', { class: 'muted' }, 'No extensions (an X.509 v1 certificate).')));

  const ids = [
    ['SHA-256 fingerprint', x.sha256, 'The certificate’s identity'],
    ['Key fingerprint (SPKI SHA-256)', k.spkiSha256, 'Stays the same across renewals with the same key: pin this'],
    ['Serial number', x.serial, `X.509 v${x.version}`],
    ['SHA-1 fingerprint', x.sha1, 'An identifier for searching, never for trust'],
  ];
  out.push(h('section', { class: 'xids', 'aria-label': 'Identifiers' }, ids.map(([label, value, note]) => h('div', { class: 'xid' },
    h('span', { class: 'xid-head' }, h('span', null, label), value ? copyButton(value, label.toLowerCase()) : null),
    h('span', { class: 'xid-v' }, value || 'none'), h('span', { class: 'xid-note' }, note)))));

  const stem = (cnOf(x.subject) || fp.slice(0, 16)).replace(/[^a-z0-9._-]+/gi, '_');
  out.push(h('details', { class: 'card xpem' }, h('summary', null, 'The certificate as PEM'),
    h('pre', { class: 'pem', tabindex: '0', 'aria-label': 'The certificate in PEM' }, x.pem),
    h('p', { class: 'hint' }, 'To read it with OpenSSL: ', h('code', null, `openssl x509 -in ${stem}.pem -text -noout`))));
  void findings;
  return { out, stem };
}

/** The fields an estate source gave, when no DER was kept. */
function estateFacts(c) {
  const row = (label, ...v) => h('div', null, h('dt', null, label), h('dd', null, ...v));
  return h('section', { class: 'card' }, h('dl', { class: 'facts' },
    row('Subject', c.subject || 'not recorded'), row('Issuer', c.issuer || 'not recorded'),
    row('Public key', keyText(c), c.keyBits ? null : h('div', { class: 'hint' }, c.keyLengthNote || '')),
    row('Signature', c.signatureAlgorithm || 'not recorded'),
    row('Valid until', c.notAfter ? fmtDate(c.notAfter) : 'not recorded', ' ', expiryBadge(c)),
    row('Names', c.dnsNames || 'none recorded'),
    h('div', null, h('dt', null, 'Serial'), h('dd', { class: 'mono' }, c.serial || 'not recorded')),
    c.extKeyUsage ? row('Extended key usage', c.extKeyUsage) : null, c.keyUsage ? row('Key usage', c.keyUsage) : null,
    c.policyClass && c.policyClass !== 'unknown' ? row('Validation type', c.policyClass) : null,
    c.lifetimeDays ? row('Lifetime', `${c.lifetimeDays} days`) : null, c.wildcards ? row('Wildcard names', c.wildcards) : null,
    c.cnOnly ? row('Names', 'Common name only; no subject alternative name (modern clients will reject it)') : null,
    h('div', null, h('dt', null, 'SHA-256 fingerprint'), h('dd', { class: 'mono' }, c.fingerprint))));
}

export async function render(root, { args, query }) {
  const fp = String(args[0] || '').toLowerCase();
  if (!validFingerprint(fp)) { location.hash = '#/inventory/certificates'; return null; }
  const scan = query && query.get('scan');
  root.appendChild(skeleton(4));
  const orNull = (p) => p.catch((e) => { if (e && e.status === 404) return null; throw e; });
  const [d, xr] = await Promise.all([orNull(api.certificate(fp)), orNull(api.certificateX509(fp, /^\d+$/.test(scan || '') ? scan : ''))]);
  const x = xr && xr.der ? xr.x509 : null;
  const ribbon = x ? await chainRibbon(fp, xr.source) : null;
  clear(root);
  if (!d && !xr) {
    root.appendChild(crumbs([['Inventory', '#/inventory'], ['Certificates', '#/inventory/certificates'], ['Not found']]));
    root.appendChild(h('div', { class: 'card' }, h('h1', null, 'This certificate is not known'), h('p', { class: 'muted' }, 'No scan, upload or import has seen a certificate with this fingerprint.')));
    return null;
  }
  const c = d ? d.certificate : null;
  const title = (x && cnOf(x.subject)) || (c && c.name) || 'Certificate';
  root.appendChild(crumbs([['Inventory', '#/inventory'], ['Certificates', '#/inventory/certificates'], [title]]));
  if (ribbon) root.appendChild(ribbon);
  const built = x ? x509Sections(x, fp, d ? (d.findingDetails || []).length : null) : null;
  root.appendChild(h('div', { class: 'page-head xhead' },
    h('div', null,
      x ? h('div', { class: 'xtags' }, h('span', { class: 'xtag' }, kindWords(x)), x.validation ? h('span', { class: 'xtag' }, `${x.validation} validated`) : null,
        h('span', { class: 'xtag' }, `X.509 v${x.version}`), x.selfSigned ? h('span', { class: 'xtag xtag-warn' }, 'self-signed') : null) : null,
      h('h1', null, title),
      h('div', { class: 'sub' }, x ? [orgOf(x.subjectParts) ? `${orgOf(x.subjectParts)} · ` : '', `issued by ${cnOf(x.issuer) || 'an unnamed issuer'}`] : `${c.role} certificate`)),
    x ? h('div', { class: 'row' },
      button('Copy PEM', async (e) => { try { await navigator.clipboard.writeText(x.pem); e.currentTarget.textContent = 'Copied'; } catch { /* refused */ } }, 'secondary'),
      button('Download .pem', () => api.downloadBlob(`${built.stem}.pem`, x.pem, 'application/x-pem-file'), 'secondary')) : null));
  if (!ribbon && xr && xr.source && validId(xr.source.assetId)) {
    root.appendChild(h('p', { class: 'served-by' }, 'Served by ', h('a', { href: `#/endpoints/${xr.source.assetId}?tab=configuration` }, xr.source.assetName || 'the endpoint'),
      `, certificate ${xr.source.position + 1} of ${xr.source.chainLength}. `, h('a', { href: `#/endpoints/${xr.source.assetId}?tab=configuration` }, 'Back to the chain')));
  }
  if (built) root.append(...built.out);
  else {
    root.appendChild(estateFacts(c));
    if (xr && xr.reason) root.appendChild(h('p', { class: 'hint mt' }, xr.reason));
  }
  if (!d) return null;

  root.appendChild(h('section', { class: 'card xcard', 'aria-labelledby': 'x-seen' }, h('div', { class: 'cfg-head' }, h('h2', { id: 'x-seen' }, 'Seen on'),
    h('span', { class: 'cfg-aside' }, '“Key” says only what the sensor checked: it reads a property and never opens a key.')),
    h('div', { class: 'seenwrap' }, (d.places || []).map((p) => h(validId(p.systemId) ? 'a' : 'div', { class: 'seencard', href: validId(p.systemId) ? systemHref(p.systemId) : null },
      h('b', null, p.systemName || 'unassigned'),
      h('span', null, `${classLabel(p.sourceClass)} · ${p.method}`),
      h('span', { class: 'muted' }, [p.position || p.location, p.privateKey ? keyAssociation(p.privateKey) : null, fmtDate(p.observedAt)].filter(Boolean).join(' · ')))))));

  root.appendChild(h('section', { class: 'card xcard', 'aria-labelledby': 'x-find' }, h('h2', { id: 'x-find' }, 'Findings'),
    d.findingDetails && d.findingDetails.length
      ? d.findingDetails.map((f) => h('div', { class: 'finding' },
        h('div', { class: 'finding-head' }, badge(f.severity, f.severity === 'critical' || f.severity === 'high' ? 'bad' : 'warn'), ' ', h('b', null, f.title)),
        h('p', null, f.detail || ''), f.remediation ? h('p', { class: 'hint' }, f.remediation) : null, citations(f.citations)))
      : h('p', { class: 'hint' }, 'No finding applies to this certificate on the current evidence.')));
  return null;
}
