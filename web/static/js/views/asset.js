// One endpoint: readiness, TLS hygiene, TLS detail, findings and history.
import { h, clear, fmtDate, fmtDay, INTERVALS, intervalLabel } from '../dom.js';
import { api, ApiError } from '../api.js';
import { historyChart, levelClass, levelName } from '../charts.js';
import { levelBadge, bandBadge, bandTone, sevBadge, evidenceBadge, statusPill, citations, button, empty, toast, modal, confirmDialog,
  scanProgress, badge, certExpiry } from '../ui.js';

export async function render(root, { args, query }) {
  const id = Number(args[0]);
  const viewScanId = Number(query.get('scan')) || null;
  let stopped = false, timer = null;
  let tab = query.get('tab') || 'overview';

  const head = h('div');
  const body = h('div');
  root.append(head, body);

  // The data we render from.
  let asset = null, ev = null, rep = null, history = [], shown = null;

  const loadResult = async (scan) => {
    if (!scan) { ev = rep = null; return; }
    [ev, rep] = await Promise.all([api.evaluation(scan.id), api.report(scan.id)]);
  };

  const refresh = async () => {
    if (stopped) return;
    clearTimeout(timer);
    try {
      asset = await api.asset(id);
      history = await api.history(id);
      const wanted = viewScanId ? { id: viewScanId } : asset.lastDone;
      if (!shown || !wanted || shown.id !== wanted.id) {
        shown = wanted;
        await loadResult(shown);
      }
      paint();
      const active = asset.latest && (asset.latest.status === 'queued' || asset.latest.status === 'running');
      if (active) timer = setTimeout(pollActive, 700);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        clear(body).appendChild(empty('This endpoint no longer exists', null, button('Back to endpoints', () => { location.hash = '#/assets'; }, 'primary')));
        return;
      }
      if (!stopped) toast(e.message, 'error');
    }
  };

  // While a scan is active, poll it quickly and repaint only the progress panel.
  const pollActive = async () => {
    if (stopped) return;
    try {
      const a = await api.asset(id);
      asset = a;
      const l = a.latest;
      if (l && (l.status === 'queued' || l.status === 'running')) {
        const detail = await api.scan(l.id);
        paintProgress(detail.scan, detail.events);
        timer = setTimeout(pollActive, 700);
      } else {
        if (l && l.status === 'failed') toast(`Scan failed: ${l.error}`, 'error');
        else if (l && l.status === 'done') toast('Scan complete', 'success');
        shown = null;
        await refresh();
      }
    } catch (e) { if (!stopped) timer = setTimeout(pollActive, 2000); }
  };

  const progressBox = h('div');
  const paintProgress = (scan, events) => {
    clear(progressBox).appendChild(scanProgress(scan, events, async () => {
      try { await api.cancelScan(scan.id); toast('Scan canceled'); shown = null; refresh(); } catch (e) { toast(e.message, 'error'); }
    }));
  };

  const startScan = async () => {
    try {
      const r = await api.scanAsset(id);
      toast(r.alreadyActive ? 'A scan is already in progress' : 'Scan started', 'success');
      shown = null;
      await refresh();
    } catch (e) { toast(e.message, 'error'); }
  };

  const paint = () => {
    const a = asset;
    const active = a.latest && (a.latest.status === 'queued' || a.latest.status === 'running');
    clear(head);
    head.appendChild(h('p', null, h('a', { href: '#/assets' }, '← Endpoints')));
    head.appendChild(h('div', { class: 'page-head' },
      h('div', null, h('h1', null, a.name),
        h('div', { class: 'sub' }, h('code', null, a.address), a.tags.length ? h('span', null, ' ', a.tags.map((t) => h('span', { class: 'tag' }, t))) : null),
        a.notes ? h('p', { class: 'muted' }, a.notes) : null),
      h('div', { class: 'row' },
        button(active ? 'Scanning…' : 'Scan now', startScan, 'primary', { class: 'btn btn-primary', disabled: active }),
        scheduleSelect(a),
        button('Edit', () => editDialog(a, refresh)),
        button('Delete', async () => {
          if (await confirmDialog('Delete this endpoint?', `“${a.name}” and its whole scan history will be permanently deleted.`)) {
            try { await api.deleteAsset(id); toast('Endpoint deleted'); location.hash = '#/assets'; } catch (e) { toast(e.message, 'error'); }
          }
        }, 'danger', { class: 'btn btn-danger' }))));

    if (active) {
      clear(progressBox);
      head.appendChild(progressBox);
      api.scan(a.latest.id).then((d) => paintProgress(d.scan, d.events)).catch(() => {});
    }

    clear(body);
    if (viewScanId && shown) {
      const s = history.find((x) => x.scanId === viewScanId);
      body.appendChild(h('div', { class: 'viewing' }, h('b', null, 'Viewing a past scan'),
        h('span', null, s ? fmtDate(s.at) : ''), '(read-only)', h('a', { href: `#/assets/${id}` }, 'Back to the latest result')));
    }
    if (a.latest && a.latest.status === 'failed' && !(a.lastDone && a.lastDone.id > a.latest.id) && !viewScanId) {
      body.appendChild(h('div', { class: 'callout bad', role: 'alert' }, h('b', null, 'The last scan failed: '), a.latest.error));
    }
    if (!ev) {
      if (!active && !(a.latest && a.latest.status === 'failed')) {
        body.appendChild(empty('Not scanned yet', 'Run a scan to see this endpoint’s PQC readiness, TLS hygiene and findings.',
          button('Scan now', startScan, 'primary')));
      }
      if (history.length) body.appendChild(historySection());
      return;
    }
    if (rep.incomplete) {
      body.appendChild(h('div', { class: 'warnbanner', role: 'status' },
        'This scan was incomplete: some probes were inconclusive or hit a limit. A missing finding is not proof that the problem is absent.'));
    }
    const tabs = [['overview', 'Overview'], ['tls', 'TLS details'], ['findings', `Findings (${ev.findings.length})`], ['history', `History (${history.length})`]];
    body.appendChild(h('div', { class: 'tabs', role: 'tablist' }, tabs.map(([k, label]) =>
      h('button', { type: 'button', class: 'tab', role: 'tab', id: `tab-${k}`, 'aria-selected': String(tab === k),
        onclick: () => { tab = k; paint(); } }, label))));
    body.appendChild(tab === 'tls' ? tlsTab() : tab === 'findings' ? findingsTab() : tab === 'history' ? historySection() : overviewTab());
  };

  // ---- overview -------------------------------------------------------------------------------

  const overviewTab = () => {
    const r = ev.readiness;
    const lvClass = levelClass(r.level);
    const dim = (title, d) => h('div', { class: 'dim' },
      h('h4', null, title, badge(d.status, 'neutral'), evidenceBadge(d.evidence)),
      h('div', null, d.detail), citations(d.citations));
    return h('div', { class: 'grid two' },
      h('section', { class: 'card', 'aria-labelledby': 'rd-h' },
        h('h2', { id: 'rd-h' }, 'PQC readiness'),
        h('div', { class: 'readiness' },
          h('div', { class: `bigLevel ${lvClass}` }, r.level < 0 ? '?' : `L${r.level}`, h('small', null, r.label)),
          h('div', null, h('p', null, r.summary),
            r.hndlExposed ? h('div', { class: 'callout' }, h('b', null, 'Exposed to harvest-now-decrypt-later. '),
              'An adversary recording this endpoint’s traffic today could read it once a large enough quantum computer exists.') : null)),
        h('div', { class: 'scale', role: 'img', 'aria-label': `Level ${r.level} of 4` }, [0, 1, 2, 3, 4].map((l) =>
          h('span', { class: `${levelClass(l)}${l === r.level ? ' on' : ''}`, title: levelName(l) }, `L${l}`))),
        dim('Key establishment', r.keyEstablishment),
        dim('Authentication', r.authentication),
        dim('Symmetric strength', r.symmetric),
        r.pqGroups.length ? h('p', null, h('b', null, 'Post-quantum groups accepted: '), r.pqGroups.join(', ')) : null,
        h('h3', null, 'What to do next'),
        h('ol', { class: 'next' }, r.nextSteps.map((s) => h('li', null, s))),
        h('details', null, h('summary', null, 'Sources for this assessment'), citations(r.citations)),
        h('p', { class: 'hint' }, 'The level scale is this product’s own; each fact above cites its standard.')),
      h('section', { class: 'card', 'aria-labelledby': 'gr-h' },
        h('h2', { id: 'gr-h' }, 'TLS hygiene'),
        hygieneBody(ev.hygiene),
        h('dl', { class: 'kv' },
          h('dt', null, 'Scanned'), h('dd', null, fmtDate(rep.started)),
          h('dt', null, 'Duration'), h('dd', null, `${rep.durationMs < 1000 ? `${rep.durationMs} ms` : `${(rep.durationMs / 1000).toFixed(1)} s`}, ${rep.connections} connections`),
          h('dt', null, 'Addresses'), h('dd', null, (rep.addresses || []).join(', ') || rep.address),
          h('dt', null, 'Evaluation'), h('dd', null, ev.version))));
  };

  // The rating is worked out from the findings on the same result, so every point taken off is listed with its finding.
  const hygieneBody = (g) => {
    if (!g) {
      return h('p', { class: 'muted' }, 'This scan was evaluated by an earlier version, which used a different rating. Scan again to rate it.');
    }
    const tone = { good: 'lv3', ok: 'lv2', warn: 'lv1', bad: 'lv0', neutral: 'lvu' }[bandTone(g.band)];
    return h('div', null,
      h('div', { class: 'row' }, h('div', { class: `bigLevel ${tone}` }, g.score < 0 ? '–' : String(g.score), h('small', null, g.band)),
        h('div', null, h('div', null, h('b', null, g.score < 0 ? 'Not rated' : `${g.score} out of 100`)),
          h('div', { class: 'muted' }, 'how well the endpoint is configured; this product’s own score'))),
      h('h3', null, 'How it was scored'),
      g.deductions.length ? h('ul', { class: 'deductions' }, g.deductions.map((d) =>
        h('li', null, sevBadge(d.severity), ' ', d.title, h('span', { class: 'muted' }, ` (${d.finding})`), h('b', { class: 'pts' }, ` −${d.points}`))))
        : h('p', { class: 'muted' }, 'No points were taken off.'),
      g.ceiling ? h('p', null, h('b', null, `Limited to ${g.ceiling.score}: `), g.ceiling.reason, '.') : null,
      h('h3', null, 'Not measured'),
      h('ul', { class: 'muted' }, g.notMeasured.map((m) => h('li', null, m))),
      h('details', null, h('summary', null, 'About this score'), h('p', { class: 'muted' }, g.methodology)));
  };

  // ---- TLS details ----------------------------------------------------------------------------

  const tlsTab = () => {
    const wrap = h('div', { class: 'stack' });

    wrap.appendChild(h('section', { class: 'card' }, h('h2', null, 'Protocol versions'),
      h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
        h('thead', null, h('tr', null, ['Version', 'Supported', 'Evidence', 'Detail'].map((c) => h('th', { scope: 'col' }, c)))),
        h('tbody', null, rep.protocols.map((p) => h('tr', null,
          h('td', null, h('b', null, p.version)),
          h('td', null, p.evidence === 'inconclusive' ? badge('unknown', 'warn') : p.supported ? badge('Yes', legacy(p.version) ? 'bad' : 'good') : badge('No', 'neutral')),
          h('td', null, p.evidence),
          h('td', { class: 'muted' }, p.detail || ''))))))));

    const versions = [...new Set(rep.suites.map((s) => s.version))];
    for (const v of versions) {
      const pref = (rep.preference || []).find((p) => p.version === v && p.subject === 'suites');
      const rows = rep.suites.filter((s) => s.version === v);
      wrap.appendChild(h('section', { class: 'card' },
        h('h2', null, `Cipher suites, ${v}`), h('p', { class: 'muted' }, prefText(pref)),
        h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
          h('thead', null, h('tr', null, ['#', 'Suite', 'Cipher', 'Key exchange', 'Flags', 'IANA'].map((c) => h('th', { scope: 'col' }, c)))),
          h('tbody', null, rows.map((s) => h('tr', null,
            h('td', { class: 'num' }, s.rank || '–'), h('td', null, h('code', null, s.name)),
            h('td', null, s.cipher === 'NULL' ? 'none' : `${s.cipher}-${s.keyBits} ${s.mode}`),
            h('td', null, s.kx || 'TLS 1.3'),
            h('td', null, suiteFlags(s)),
            h('td', null, badge(ianaLabel(s.ianaRecommended), s.ianaRecommended === 'Y' ? 'good' : s.ianaRecommended === 'D' ? 'bad' : 'neutral')))))))));
    }

    if (rep.groups && rep.groups.length) {
      const gv = [...new Set(rep.groups.map((g) => g.version))];
      wrap.appendChild(h('section', { class: 'card' }, h('h2', null, 'Key-exchange groups'),
        gv.map((v) => {
          const pref = (rep.preference || []).find((p) => p.version === v && p.subject === 'groups');
          return h('div', null, h('h3', null, v), h('p', { class: 'muted' }, prefText(pref)),
            h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
              h('thead', null, h('tr', null, ['#', 'Group', 'Post-quantum', 'IANA'].map((c) => h('th', { scope: 'col' }, c)))),
              h('tbody', null, rep.groups.filter((g) => g.version === v).map((g) => h('tr', null,
                h('td', { class: 'num' }, g.rank || '–'), h('td', null, h('code', null, g.name)),
                h('td', null, g.pq ? badge(g.hybrid ? 'Hybrid post-quantum' : 'Post-quantum', g.obsolete ? 'warn' : 'good') : h('span', { class: 'muted' }, 'classical'),
                  g.obsolete ? badge('obsolete draft', 'warn') : null),
                h('td', null, badge(ianaLabel(g.ianaRecommended), g.ianaRecommended === 'Y' ? 'good' : g.ianaRecommended === 'D' ? 'bad' : 'neutral')))))))); })));
    }
    if (rep.dh) {
      wrap.appendChild(h('section', { class: 'card' }, h('h2', null, 'Diffie-Hellman'),
        h('p', null, `${rep.dh.primeBits}-bit prime (fingerprint ${rep.dh.primeSha256.slice(0, 16)}…), sampled from `, h('code', null, rep.dh.suite))));
    }

    const f = rep.features || {};
    const feat = (label, v, yes, no) => v === null || v === undefined ? null
      : h('tr', null, h('td', null, label), h('td', null, v ? yes : no));
    const rows = [
      feat('Secure renegotiation (RFC 5746)', f.secureRenegotiation, badge('advertised', 'good'), badge('not advertised', 'warn')),
      feat('Extended master secret (RFC 7627)', f.extendedMasterSecret, badge('supported', 'good'), badge('not offered', 'neutral')),
      feat('Session tickets', f.sessionTickets, badge('offered', 'neutral'), badge('not offered', 'neutral')),
      feat('OCSP stapling', f.ocspStapling, badge('supported', 'good'), badge('not offered', 'neutral')),
      feat('TLS compression', f.compression, badge('accepted', 'bad'), badge('refused', 'good')),
      feat('TLS_FALLBACK_SCSV (RFC 7507)', f.fallbackScsv, badge('enforced', 'good'), badge('not enforced', 'warn')),
    ].filter(Boolean);
    if (rows.length) wrap.appendChild(h('section', { class: 'card' }, h('h2', null, 'Server features'), h('table', { class: 'compact' }, h('tbody', null, rows))));

    if (rep.certificates && rep.certificates.length) {
      wrap.appendChild(h('section', { class: 'card' }, h('h2', null, 'Certificates'), rep.certificates.map(certBlock)));
    }
    if (rep.negotiated) {
      const n = rep.negotiated;
      wrap.appendChild(h('section', { class: 'card' }, h('h2', null, 'What a current client negotiates'),
        n.version ? h('dl', { class: 'kv' }, h('dt', null, 'Protocol'), h('dd', null, n.version), h('dt', null, 'Cipher suite'), h('dd', null, h('code', null, n.suite)),
          n.group ? [h('dt', null, 'Key exchange'), h('dd', null, n.group, ' ', n.pq ? badge('post-quantum', 'good') : badge('classical', 'neutral'))] : null,
          n.alpn ? [h('dt', null, 'ALPN'), h('dd', null, n.alpn)] : null)
          : h('p', { class: 'muted' }, `The handshake did not complete: ${n.error}`),
        h('p', { class: 'hint' }, 'The client is Go’s crypto/tls, which offers the X25519MLKEM768 hybrid first.')));
    }
    if (rep.notes && rep.notes.length) {
      wrap.appendChild(h('section', { class: 'card' }, h('h2', null, 'Notes on the scan'), h('ul', null, rep.notes.map((n) => h('li', null, n)))));
    }
    return wrap;
  };

  const certBlock = (c) => {
    const leaf = c.chain[0];
    return h('div', { class: 'chain' },
      h('h3', null, leaf.subject, ' ', h('span', { class: 'muted' }, `(${c.source})`)),
      h('dl', { class: 'kv' },
        h('dt', null, 'Issuer'), h('dd', null, leaf.issuer),
        h('dt', null, 'Public key'), h('dd', null, `${leaf.publicKey.algorithm}${leaf.publicKey.bits ? ` ${leaf.publicKey.bits}-bit` : ''}${leaf.publicKey.curve ? ` ${leaf.publicKey.curve}` : ''}`,
          h('span', { class: 'muted' }, ` · OID ${leaf.publicKey.oid}`)),
        h('dt', null, 'Signature'), h('dd', null, leaf.signatureAlgorithm.name, h('span', { class: 'muted' }, ` · OID ${leaf.signatureAlgorithm.oid}`)),
        h('dt', null, 'Valid'), h('dd', null, `${fmtDay(leaf.notBefore)} to ${fmtDay(leaf.notAfter)} `, certExpiry(leaf.notAfter)),
        h('dt', null, 'Trust'), h('dd', null, c.trusted ? badge('chain builds to a trusted root', 'good') : badge('not trusted', 'bad'),
          c.trustError ? h('div', { class: 'muted' }, c.trustError) : null),
        h('dt', null, 'Name'), h('dd', null, c.nameMatches ? badge('matches this host', 'good') : badge('does not match', 'bad'),
          c.nameError ? h('div', { class: 'muted' }, c.nameError) : null),
        h('dt', null, 'Names'), h('dd', null, [...(leaf.dnsNames || []), ...(leaf.ipAddresses || [])].join(', ') || '–'),
        c.chain.length > 1 ? [h('dt', null, 'Chain'), h('dd', null, `${c.chain.length} certificates: ${c.chain.map((x) => x.subject).join(' → ')}`)] : null,
        h('dt', null, 'SHA-256'), h('dd', null, h('code', null, leaf.sha256))));
  };

  // ---- findings -------------------------------------------------------------------------------

  const findingsTab = () => {
    if (!ev.findings.length) return h('div', { class: 'card' }, h('p', null, 'No findings. 🎉'));
    const counts = ev.counts || {};
    return h('div', null,
      h('div', { class: 'row', 'aria-label': 'Finding counts' }, ['critical', 'high', 'medium', 'low', 'info'].filter((s) => counts[s]).map((s) => h('span', null, sevBadge(s), ` ${counts[s]}`))),
      h('div', { class: 'findings mt' }, ev.findings.map((f) => h('article', { class: `finding s-${f.severity}` },
        h('div', { class: 'finding-head' }, sevBadge(f.severity), h('strong', null, f.title), evidenceBadge(f.evidence), badge(f.category, 'neutral')),
        h('div', { class: 'detail' }, f.detail),
        h('div', { class: 'fix' }, h('b', null, 'Fix: '), f.remediation),
        citations(f.citations)))));
  };

  // ---- history --------------------------------------------------------------------------------

  const historySection = () => {
    const done = history.filter((p) => p.status === 'done');
    const wrap = h('div', { class: 'stack' });
    wrap.appendChild(h('section', { class: 'card' }, h('h2', null, 'Readiness over time'), historyChart(history),
      h('p', { class: 'hint' }, 'Each point is a completed scan, labelled with its TLS hygiene score.')));

    const diffBox = h('div');
    const loadDiff = async (from, to) => {
      clear(diffBox).appendChild(h('p', { class: 'muted' }, 'Comparing…'));
      try {
        const d = await api.diff(id, from, to);
        clear(diffBox).appendChild(diffView(d));
      } catch (e) { clear(diffBox).appendChild(h('p', { class: 'muted' }, e.status === 409 ? 'At least two completed scans are needed to compare.' : e.message)); }
    };
    const opts = (sel) => done.slice().reverse().map((p) => h('option', { value: String(p.scanId), selected: sel === p.scanId }, `${fmtDate(p.at)} · ${p.band} ${p.score} · L${p.readinessLevel}`));
    const fromSel = h('select', { 'aria-label': 'Compare from' }, opts(done.length > 1 ? done[done.length - 2].scanId : null));
    const toSel = h('select', { 'aria-label': 'Compare to' }, opts(done.length ? done[done.length - 1].scanId : null));
    wrap.appendChild(h('section', { class: 'card' }, h('h2', null, 'What changed'),
      done.length < 2 ? h('p', { class: 'muted' }, 'Scan this endpoint again to compare results over time.')
        : h('div', null, h('div', { class: 'row' }, 'Compare', fromSel, 'with', toSel,
          button('Compare', () => loadDiff(fromSel.value, toSel.value), 'secondary')), diffBox)));
    if (done.length >= 2) loadDiff(null, null);

    wrap.appendChild(h('section', { class: 'card' }, h('h2', null, 'All scans'),
      h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
        h('thead', null, h('tr', null, ['When', 'Status', 'Readiness', 'TLS hygiene', 'Findings', ''].map((c) => h('th', { scope: 'col' }, c)))),
        h('tbody', null, history.slice().reverse().map((p) => h('tr', null,
          h('td', null, fmtDate(p.at)), h('td', null, statusPill(p.status), p.error ? h('div', { class: 'hint' }, p.error) : null),
          h('td', null, p.status === 'done' ? levelBadge(p.readinessLevel) : '–'), h('td', null, p.status === 'done' ? bandBadge(p.band, p.score) : '–'),
          h('td', null, p.status === 'done' ? `${p.critical} critical, ${p.high} high` : '–'),
          h('td', null, p.status === 'done' ? h('a', { href: `#/assets/${id}?scan=${p.scanId}` }, 'Open') : null))))))));
    return wrap;
  };

  const diffView = (d) => {
    const x = d.diff;
    return h('div', null, h('p', null, h('b', null, x.summary)),
      x.changes.length ? h('div', null, x.changes.map((c) => h('div', { class: 'change' },
        h('span', { class: `impact imp-${c.impact}` }, c.impact),
        h('span', null, h('b', null, `${c.area}: `), c.subject,
          c.before || c.after ? h('span', { class: 'muted' }, ` · ${c.before || ''}${c.before && c.after ? ' → ' : ''}${c.after || ''}`) : null)))) : null);
  };

  await refresh();
  return () => { stopped = true; clearTimeout(timer); };
}

// ---- helpers ---------------------------------------------------------------------------------

const legacy = (v) => ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'].includes(v);
const ianaLabel = (r) => ({ Y: 'Recommended', N: 'Not recommended', D: 'Discouraged' }[r] || r);

function prefText(p) {
  if (!p) return '';
  return { server: 'Order set by the server (ranked).', client: 'The server follows the client’s order (no ranking).',
    mixed: 'The order depends on what the client offers (no ranking).', unknown: 'Order not determined.' }[p.order] || '';
}

function suiteFlags(s) {
  const out = [];
  if (s.cipher === 'NULL') out.push(badge('no encryption', 'bad'));
  if (s.export) out.push(badge('export', 'bad'));
  if (s.anon) out.push(badge('anonymous', 'bad'));
  if (s.cipher === 'RC4') out.push(badge('RC4', 'bad'));
  if (s.blockBits === 64 && !s.export) out.push(badge('64-bit block', 'warn'));
  if (s.kx && !s.ephemeral && ['RSA', 'DH', 'ECDH'].includes(s.kx)) out.push(badge('no forward secrecy', 'warn'));
  if (s.aead) out.push(badge('AEAD', 'good'));
  return out.length ? out.map((b) => h('span', null, b, ' ')) : h('span', { class: 'muted' }, '–');
}

function scheduleSelect(a) {
  const sel = h('select', { 'aria-label': 'Automatic rescans', onchange: async (e) => {
    try { await api.patchAsset(a.id, { intervalSeconds: Number(e.target.value) }); toast(`Rescans: ${intervalLabel(Number(e.target.value))}`, 'success'); }
    catch (ex) { toast(ex.message, 'error'); }
  } }, INTERVALS.map(([s, label]) => h('option', { value: String(s), selected: a.intervalSeconds === s }, `Rescan: ${label}`)));
  return sel;
}

function editDialog(a, done) {
  modal('Edit endpoint', (close) => {
    const name = h('input', { type: 'text', id: 'e-name', value: a.name });
    const tags = h('input', { type: 'text', id: 'e-tags', value: a.tags.join(', ') });
    const notes = h('textarea', { id: 'e-notes' }); notes.value = a.notes;
    const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
    return h('form', { class: 'modal-body', onsubmit: async (e) => {
      e.preventDefault();
      try {
        await api.patchAsset(a.id, { name: name.value, tags: tags.value.split(',').map((t) => t.trim()).filter(Boolean), notes: notes.value });
        toast('Saved', 'success'); close(); done();
      } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    } }, err, h('label', { for: 'e-name' }, 'Name'), name, h('label', { for: 'e-tags' }, 'Tags (comma separated)'), tags,
    h('label', { for: 'e-notes' }, 'Notes'), notes,
    h('div', { class: 'row end' }, button('Cancel', close), h('button', { type: 'submit', class: 'btn btn-primary' }, 'Save')));
  });
}

