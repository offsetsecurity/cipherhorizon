// The estate half of the end-to-end journey (PRD-003 WP-8, UX-DESIGN-002 section 8). It runs inside
// journey.mjs after the endpoint pages have been exercised, so the database already holds scanned
// endpoints; it adds imports, metadata and a proposed join, and checks every new view, including with
// hostile text in every field a person or a third-party document controls.
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { authFetch as fetch } from './authfetch.mjs';

const FIXTURE = new URL('../../testdata/interop/cbomlens-like-1.7.json', import.meta.url);
const HOSTILE = '<img src=x onerror=window.__xss=1><script>window.__xss=2</script>';
const RTL = 'safe‮evil‬ name';
const LONG = 'x'.repeat(400);

export async function estatePhase(t) {
  const { check, js, go, sleep, shot, api, BASE, send, viewport, clickText } = t;
  const post = async (path, body, headers = {}) => fetch(`${BASE}${path}`, {
    method: 'POST', headers: { 'X-Requested-With': 'cipherhorizon', 'Content-Type': 'application/json', ...headers }, body });
  const patch = async (path, obj) => fetch(`${BASE}${path}`, {
    method: 'PATCH', headers: { 'X-Requested-With': 'cipherhorizon', 'Content-Type': 'application/json' }, body: JSON.stringify(obj) });
  const tmp = mkdtempSync(join(tmpdir(), 'estate-e2e-'));
  const setFile = async (selector, path) => {
    await send('DOM.enable');
    const doc = await send('DOM.getDocument', { depth: 0 });
    const n = await send('DOM.querySelector', { nodeId: doc.root.nodeId, selector });
    await send('DOM.setFileInputFiles', { files: [path], nodeId: n.nodeId });
  };
  const submitDialog = () => js(`document.querySelector('.modal form').requestSubmit();`);
  const text = () => js(`return document.querySelector('main').innerText`);

  // ---- E1: Systems ranks every system, and every row says why (secondary since PRD-005) ---------------------
  await go('#/systems');
  await sleep(1200);
  const est = await api('/api/v1/estate');
  const e1 = await js(`return { rows: document.querySelectorAll('main tbody tr:not(.why-row)').length,
    head: document.querySelector('h1')?.innerText, nav: document.querySelector('#nav a[aria-current=page], .sidefoot a[aria-current=page]')?.innerText.trim(),
    marker: document.querySelectorAll('main .badge').length, bad: /\\bgrade\\b/i.test(document.querySelector('main').innerText) }`);
  check('E2E-20.1', 'Systems lists every system in rank order, its sidebar link marked as the current page', e1.head === 'Systems' && e1.rows === est.ranking.length && e1.rows >= 3 && /Systems/.test(e1.nav), JSON.stringify(e1));
  check('E2E-20.2', 'no letter grade is offered anywhere on the estate', !e1.bad);
  await js(`document.querySelector('main tbody tr button')?.click()`);
  await sleep(200);
  const why = await js(`const r = document.querySelector('.why-row:not([hidden])'); return { shown: !!r, rules: r ? r.querySelectorAll('.why-rule').length : 0,
    links: r ? [...r.querySelectorAll('a')].map((a) => [a.protocol, a.rel]) : [], expanded: document.querySelector('main tbody tr button')?.getAttribute('aria-expanded') }`);
  check('E2E-20.3', 'a row expands to four rules with cited https sources, and the control says it is expanded',
    why.shown && why.rules === 4 && why.links.length > 0 && why.links.every(([p, r]) => p === 'https:' && /noopener/.test(r)) && why.expanded === 'true', JSON.stringify(why));
  await shot('estate-ranked');

  // ---- E2: entering what only a person knows moves a system and removes "evidence only" --------------------
  const top = est.ranking[0];
  const target = est.ranking.find((r) => r.evidenceOnly && r.evidence === 'observed' && r.systemId !== top.systemId) || est.ranking[1];
  await go(`#/systems/${target.systemId}`);
  await sleep(1200);
  check('E2E-21.1', 'the system page shows why it is where it is, the editor, services, certificates, links, imports, coverage, export and history',
    (await js(`return [...document.querySelectorAll('main section h2')].map((h) => h.innerText).join('|')`)).split('|').length >= 8, await js(`return [...document.querySelectorAll('main section h2')].map((h) => h.innerText).join('|')`));
  await js(`document.getElementById('sys-dataLifetimeYears').value = '30'; document.getElementById('sys-exposure').value = 'internet'; document.getElementById('sys-criticality').value = 'high';
    document.getElementById('sys-owner').value = 'Payments'; document.getElementById('sys-reason').value = 'onboarding'; document.querySelector('.system-form').requestSubmit();`);
  await sleep(1200);
  const est2 = await api('/api/v1/estate');
  const moved = est2.ranking.find((r) => r.systemId === target.systemId);
  check('E2E-21.2', 'saving details from the page moves the system and it stops saying it rests on evidence only', moved.rank <= target.rank && !moved.evidenceOnly && /past 2030/.test(moved.reasons[0].text), JSON.stringify({ was: target.rank, now: moved.rank }));
  const hist = await text();
  check('E2E-21.3', 'the change is in the history with its reason', /onboarding/.test(hist) && /dataLifetimeYears: not provided → 30/.test(hist));
  const certsText = await js(`return document.getElementById('sec-certs')?.innerText || ''`);
  check('E2E-21.4', 'the certificate section shows the key size, and never claims a private key does not exist', /-bit/.test(certsText) && !/no private key/i.test(certsText), certsText.slice(0, 160));
  await shot('system-page');

  // ---- E3: import flow: file, system, detected producer, and what was not interpreted --------------------
  await go('#/imports');
  await sleep(700);
  check('E2E-22.0', 'with nothing imported, the page says what an import does', /Nothing imported yet/.test(await text()));
  await clickText('Import a CBOM');
  await sleep(300);
  await setFile('#import-file', FIXTURE.pathname.replace(/^\/([A-Za-z]:)/, '$1'));
  await submitDialog(); // no system named: refused
  await sleep(300);
  check('E2E-22.1', 'an import with no system named is refused before anything is sent',
    /Say which system/.test(await js(`return document.querySelector('.modal .callout.bad')?.innerText || ''`)));
  await js(`document.getElementById('import-new').value = 'imported-lens-host'`);
  await submitDialog();
  await sleep(1200);
  const imp = await js(`return document.querySelector('.modal')?.innerText || ''`);
  check('E2E-22.2', 'the result names the detected producer, the file\'s own subject as a claim, and the parts not interpreted',
    /detected producer/i.test(imp) && /CBOM-Lens/.test(imp) && /not interpreted/i.test(imp) && /never overwrite/.test(imp), imp.slice(0, 200));
  await shot('import-result', { full: false });
  await clickText('Close', "document.querySelector('.modal')");
  await sleep(300);
  await go('#/systems');
  await sleep(1000);
  const listed = await js(`return [...document.querySelectorAll('main tbody tr')].find((r) => r.innerText.includes('imported-lens-host'))?.innerText || ''`);
  check('E2E-22.3', 'the imported system is ranked and labelled as known only from an import', /imported only/.test(listed) && /no owner details yet/.test(listed), listed);
  // Re-importing the same bytes is a duplicate, not a second copy.
  const lensSystem = (await api('/api/v1/systems')).systems.find((x) => x.name === 'imported-lens-host');
  const dup = await (await post(`/api/v1/imports?system=${lensSystem.id}`, readFileSync(FIXTURE, 'utf8'))).json();
  check('E2E-22.4', 'the same document imported again changes nothing', dup.duplicate === true);

  // ---- E4: a proposed join reaches the review queue and can be confirmed with its explanation -----------
  const certs = await api('/api/v1/certificates?current=1');
  const scanned = certs.certificates.find((c) => c.origins.includes('scanner'));
  const doc = readFileSync(FIXTURE, 'utf8').replaceAll('ab'.repeat(32), scanned.fingerprint);
  const docPath = join(tmp, 'same-cert.json');
  writeFileSync(docPath, doc);
  const r = await post('/api/v1/imports?newSystem=lens-holds-the-same-certificate', doc);
  check('E2E-23.0', 'a document holding the same certificate as a scanned endpoint imports', r.status === 201, r.status);
  await sleep(500);
  const proposed = await api('/api/v1/links?state=proposed');
  check('E2E-23.1', 'the shared certificate produces a proposal and never an automatic join from an import', proposed.length >= 1 && proposed.every((l) => l.state === 'proposed'), JSON.stringify(proposed.map((l) => l.state)));
  await go('#/review');
  await sleep(1000);
  const rv = await js(`return { cards: document.querySelectorAll('.link-card').length, text: document.querySelector('main').innerText,
    badge: document.getElementById('nav-review-count')?.hidden === false ? document.getElementById('nav-review-count').textContent : '' }`);
  check('E2E-23.2', 'the review queue shows each proposal with its rule, the matched value, its strength in words, and the count in the menu',
    rv.cards >= 1 && /J1/.test(rv.text) && /(strong|medium|weak)/.test(rv.text) && rv.badge === String(proposed.length) && /Confirm/.test(rv.text) && /Reject/.test(rv.text), JSON.stringify({ cards: rv.cards, badge: rv.badge }));
  await shot('review-queue');
  await clickText('Reject');
  await sleep(300);
  await js(`document.getElementById('reason-input').value = 'not the same machine'; document.querySelector('.modal form').requestSubmit();`);
  await sleep(1200);
  const after = await api('/api/v1/links?state=all');
  const rejected = after.find((l) => l.state === 'rejected');
  const trail = rejected ? await api(`/api/v1/systems/${rejected.systemId}/audit`) : [];
  check('E2E-23.3', 'rejecting from the queue records who and why in the audit trail, and the card moves to Decided',
    !!rejected && !!rejected.decidedBy && trail.some((a) => a.action === 'link-reject' && a.reason === 'not the same machine') && /Decided/.test(await text()), JSON.stringify(trail.map((a) => [a.action, a.reason])));

  // ---- E5: certificates ------------------------------------------------------------------------------
  await go('#/certificates');
  await sleep(1000);
  const c0 = await js(`return { rows: document.querySelectorAll('main tbody tr').length, summary: document.querySelector('[role=status]')?.innerText || '' }`);
  check('E2E-24.1', 'the certificates page lists certificates with their key size', c0.rows >= 1 && /-bit/.test(await text()), JSON.stringify(c0));
  await js(`const s = document.getElementById('cert-key'); s.value = 'unknown'; s.dispatchEvent(new Event('change'))`);
  await sleep(200);
  const c1 = await js(`return document.querySelector('[role=status]')?.innerText || ''`);
  check('E2E-24.2', 'a filter narrows the list and says how many remain', /\d+ of \d+ certificate/.test(c1) && c1 !== c0.summary, `${c0.summary} -> ${c1}`);
  await js(`const s = document.getElementById('cert-key'); s.value = ''; s.dispatchEvent(new Event('change'))`);
  await js(`document.querySelector('main tbody a')?.click()`);
  await sleep(900);
  const cp = await text();
  check('E2E-24.3', 'a certificate page shows where it was seen and how, with key wording that says what was checked', /where it was seen/i.test(cp) && /sha-256 fingerprint/i.test(cp) && !/no private key/i.test(cp), cp.slice(0, 100));
  await shot('certificate-page');

  // ---- E6: M-23-02 export is reachable and has nine items ------------------------------------------------
  const m = await api(`/api/v1/systems/${target.systemId}/m2302.json`);
  check('E2E-25.1', 'the M-23-02 structure has nine items, the entered ones marked provided by the operator, and does not claim compliance',
    m.items.length === 9 && m.items.find((i) => i.number === 8)?.value === '30 years' && m.items.find((i) => i.number === 8)?.source === 'operator' && /not a statement/.test(m.statement), JSON.stringify(m.items.map((i) => i.status)));
  await go(`#/systems/${target.systemId}`);
  await sleep(900);
  check('E2E-25.2', 'the system page offers the export with wording that supports a structure and claims nothing', /M-23-02 structure \(JSON\)/.test(await js(`return document.getElementById('sec-export').innerText`)) && !/compliant/i.test(await js(`return document.getElementById('sec-export').innerText`)));

  // ---- E7: hostile text in every field a person or a document controls renders inert --------------------
  const hostileDoc = JSON.parse(readFileSync(FIXTURE, 'utf8'));
  hostileDoc.metadata.component.name = HOSTILE;
  hostileDoc.components.find((c) => c.cryptoProperties?.assetType === 'certificate').cryptoProperties.certificateProperties.subjectName = `CN=${HOSTILE},O=${RTL}`;
  hostileDoc.components.find((c) => c.cryptoProperties?.assetType === 'certificate').hashes[0].content = 'cd'.repeat(32);
  const hs = await post(`/api/v1/imports?newSystem=${encodeURIComponent(HOSTILE)}`, JSON.stringify(hostileDoc));
  const hostileSystem = (await api('/api/v1/systems')).systems.find((s) => s.name === HOSTILE);
  check('E2E-26.0', 'a document with hostile names imports into a system with a hostile name', hs.status === 201 && !!hostileSystem, hs.status);
  if (hostileSystem) {
    await patch(`/api/v1/systems/${hostileSystem.id}`, { owner: HOSTILE, notes: `${HOSTILE}\n${RTL}\n${LONG}`, hostingProvider: RTL, fismaId: LONG.slice(0, 100) });
  }
  const views = [['estate', '#/systems'], ['system', hostileSystem ? `#/systems/${hostileSystem.id}` : '#/systems'], ['certificates', '#/certificates'], ['review', '#/review'], ['imports', '#/imports']];
  const fp = 'cd'.repeat(32);
  views.push(['certificate', `#/certificates/${fp}`]);
  await js('window.__xss = undefined');
  for (const [name, hash] of views) {
    await go(hash);
    await sleep(1100);
    const v = await js(`return { fired: window.__xss ?? null, injected: document.querySelectorAll('#main img, #main script, #main iframe, #main [onerror], #main svg[onload]').length,
      shown: document.querySelector('main').innerText.includes('<img src=x'), overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth }`);
    const needsText = name !== 'review';
    check(`E2E-26.${name}`, `hostile text in the ${name} view is shown as text and never becomes markup or script`, v.fired === null && v.injected === 0 && (!needsText || v.shown || name === 'certificates') && v.overflow <= 1, JSON.stringify(v));
  }
  await go(hostileSystem ? `#/systems/${hostileSystem.id}` : '#/systems');
  await sleep(1000);
  await shot('hostile-system');

  // ---- E8: layout in dark mode and at phone width on every new view ------------------------------------------
  for (const [dark, w, label] of [[true, 1280, 'dark'], [false, 390, 'phone']]) {
    await viewport(w, w === 390 ? 844 : 900, dark, w === 390);
    for (const [name, hash] of [['estate', '#/systems'], ['system', `#/systems/${target.systemId}`], ['certificates', '#/certificates'], ['review', '#/review'], ['imports', '#/imports']]) {
      await go(hash);
      await sleep(900);
      const o = await js(`return document.documentElement.scrollWidth - document.documentElement.clientWidth`);
      check(`NFR-a11y.${label}.${name}`, `no horizontal page scroll in the ${name} view (${label})`, o <= 1, o);
      if (name === 'estate' || name === 'system') await shot(`${name}-${label}`);
    }
  }
  await viewport(1280, 900);

  // ---- E9: accessibility basics on the new views and the old addresses still work -------------------------------
  for (const [name, hash] of [['estate', '#/systems'], ['system', `#/systems/${target.systemId}`], ['certificates', '#/certificates'], ['review', '#/review'], ['imports', '#/imports']]) {
    await go(hash);
    await sleep(900);
    const unnamed = await js(`return [...document.querySelectorAll('main button, main input, main select, main textarea, main a')].filter((e) => !e.closest('[hidden]') && !(e.textContent.trim() || e.getAttribute('aria-label') || e.labels?.length || e.getAttribute('title'))).length`);
    check(`NFR-a11y.name.${name}`, `every control in the ${name} view has an accessible name`, unnamed === 0, unnamed);
  }
  await go('#/cbom');
  await sleep(500);
  check('E2E-27.1', 'the old CBOM address opens Inventory, where the CBOM download now lives', (await js(`return location.hash`)) === '#/inventory' && (await js(`return !!document.querySelector('.download-menu')`)));
}
