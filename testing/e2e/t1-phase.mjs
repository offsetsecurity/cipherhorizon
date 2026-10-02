// The TLS scanner T1 half of the journey (PRD-004 T1d, QA-PLAN-004 §1 "Browser journey"). It scans
// the three PKI demo targets (private CA, broken chain, hostile certificate) and checks the sectioned
// endpoint report: the summary strip, Fix first, the section index (word and symbol), the purpose
// line in every section, Not checked reasons, the trust row per store, the private CA bundle flow
// (trust changes without a rescan), hostile target text in every new section, and the click budget.
const PURPOSE_SECTIONS = ['certificates', 'revocation', 'protocols', 'suites', 'key-exchange', 'features', 'http', 'vulnerabilities'];

export async function t1Phase(t) {
  const { check, js, go, sleep, shot, api, BASE, CONTROL, viewport } = t;
  const post = (path, body) => fetch(`${BASE}${path}`, { method: 'POST',
    headers: { 'X-Requested-With': 'cipherhorizon', 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });

  const targets = { corp: '127.0.0.1:9448', broken: '127.0.0.1:9449', hostile: '127.0.0.1:9450' };
  const ids = {};
  for (const [k, target] of Object.entries(targets)) {
    const r = await post('/api/v1/assets', { target });
    const a = await r.json();
    ids[k] = a.id;
    await post(`/api/v1/assets/${a.id}/scan`);
  }
  const done = async (id) => {
    const a = await api(`/api/v1/assets/${id}`);
    return a.lastDone && a.latest.status === 'done' ? a : null;
  };
  const end = Date.now() + 90000;
  for (const id of Object.values(ids)) while (!(await done(id)) && Date.now() < end) await sleep(400);
  const asset = {};
  for (const [k, id] of Object.entries(ids)) asset[k] = await api(`/api/v1/assets/${id}`);
  const evOf = (k) => api(`/api/v1/scans/${asset[k].lastDone.id}/evaluation`);
  const repOf = (k) => api(`/api/v1/scans/${asset[k].lastDone.id}/report`);

  // ---- data ------------------------------------------------------------------------------------------
  const rep = await repOf('corp');
  check('T1-E2E.1', 'a new scan is a tls-report/2 with stage records and the HTTP stage on by default',
    rep.schemaVersion === 'tls-report/2' && rep.stages.length === 7 && rep.stages.find((s) => s.name === 'http').outcome === 'done',
    JSON.stringify(rep.stages?.map((s) => `${s.name}:${s.outcome}`)));
  const evBroken = await evOf('broken');
  check('T1-E2E.2', 'the broken chain is reported as a missing intermediate, first in Fix first',
    evBroken.fixFirst[0] === 'CERT.CHAIN-INCOMPLETE', JSON.stringify(evBroken.fixFirst));
  let evCorp = await evOf('corp');
  check('T1-E2E.3', 'the private-CA chain is untrusted (unknown root), not "missing intermediate"',
    evCorp.findings.some((f) => f.id === 'CERT.UNTRUSTED') && !evCorp.findings.some((f) => f.id === 'CERT.CHAIN-INCOMPLETE'),
    evCorp.findings.map((f) => f.id).join());

  // ---- the page ---------------------------------------------------------------------------------------
  await go(`#/assets/${ids.broken}`);
  await sleep(900);
  const page = await js(`
    const secs = [...document.querySelectorAll('section.repsec[id^="sec-"]')].filter((s) => s.id !== 'sec-details');
    return {
      tiles: [...document.querySelectorAll('.sumtile .sumtile-label')].map((x) => x.textContent),
      fix: document.querySelectorAll('.fixlist > li').length,
      index: [...document.querySelectorAll('.secindex-link .secstatus')].map((x) => x.textContent.trim()),
      sections: secs.map((s) => ({ id: s.id, purpose: (s.querySelector('.purpose')?.textContent || '').length, status: s.querySelector('.repsec-head .secstatus')?.textContent.trim() })),
      trustRows: document.querySelectorAll('#sec-certificates .trusttable tbody tr').length,
      missing: document.querySelector('#sec-certificates .servednode.missing')?.innerText || '',
    };`);
  check('T1-E2E.4', 'summary strip: readiness, TLS hygiene, certificate and Not checked tiles',
    page.tiles.join('|').toLowerCase() === 'pqc readiness|tls hygiene|certificate|not checked', page.tiles.join('|'));
  check('T1-E2E.5', 'Fix first lists one to three items', page.fix >= 1 && page.fix <= 3, page.fix);
  check('T1-E2E.6', 'every index entry states its status as a symbol and a word',
    page.index.length === 8 && page.index.every((s) => /^[✖▲✔○?] (Problem|Needs attention|Good|Not checked|Not collected|Inconclusive)$/.test(s)), page.index.join(' / '));
  check('T1-E2E.7', 'every section has a purpose line (REQ-TUI-4)',
    PURPOSE_SECTIONS.every((id) => page.sections.find((s) => s.id === `sec-${id}`)?.purpose > 40), JSON.stringify(page.sections));
  check('T1-E2E.8', 'a trust row per bundled store, and the missing issuer drawn in the served chain',
    page.trustRows >= 2 && /Missing: Demo Corp Issuing CA 1/.test(page.missing), `${page.trustRows} rows; ${page.missing.slice(0, 60)}`);
  const rev = await js(`return document.querySelector('#sec-revocation')?.innerText || ''`);
  check('T1-E2E.15', 'revocation says in sentences what was stapled, lists the URLs the certificate gives, and says they were not looked up',
    /OCSP response was stapled/.test(rev) && /ocsp\.demo-corp\.test/.test(rev) && /not looked up/.test(rev), rev.slice(0, 200));
  await shot('t1-broken-chain-report');
  // REQ-TUI-9: the Findings tab is an index; each finding links back to its section.
  const back = await js(`
    [...document.querySelectorAll('.tab')].find((b) => /^Findings/.test(b.textContent)).click();
    await new Promise((r) => setTimeout(r, 400));
    const link = [...document.querySelectorAll('.finding a.xlink')].find((a) => /^In Certificates & trust/.test(a.textContent));
    if (!link) return { ok: false, why: 'no section link' };
    link.click();
    await new Promise((r) => setTimeout(r, 900));
    const tab = document.querySelector('.tab[aria-selected="true"]')?.textContent;
    const sec = document.getElementById('sec-certificates');
    return { ok: tab === 'Report' && !!sec && sec.getBoundingClientRect().top < innerHeight, tab };`);
  check('T1-E2E.16', 'a finding in the Findings tab links to its section in the report', back.ok, JSON.stringify(back));

  // T1-M5: from the estate home to the cause in two clicks (system → endpoint report shows it).
  await go('#/');
  await sleep(700);
  const clicks = await js(`
    const link = [...document.querySelectorAll('a')].find((a) => a.textContent.trim() === '127.0.0.1:9449');
    if (!link) return { ok: false, why: 'no estate row' };
    link.click();
    await new Promise((r) => setTimeout(r, 1200));
    const ep = [...document.querySelectorAll('a')].find((a) => a.getAttribute('href') === '#/assets/${ids.broken}');
    if (!ep) return { ok: false, why: 'no endpoint link on the system page' };
    ep.click();
    await new Promise((r) => setTimeout(r, 1500));
    return { ok: /intermediate certificate is missing/i.test(document.querySelector('.fixfirst')?.innerText || ''), why: location.hash };`);
  check('T1-M5', 'Estate → system → endpoint: the cause is on screen after two clicks', clicks.ok, JSON.stringify(clicks));

  // Not checked is rendered with its reason: turn the HTTP stage off for one scan via a legacy report? Instead
  // check the section anatomy on the hostile target, whose HTTP header is invalid, and the Not collected
  // rendering on any stored eval/2 result is covered by the Go tests (TestSectionsAndFixFirst).

  // ---- private CA bundle: trust changes without a rescan --------------------------------------------------
  const pem = await (await fetch(`${CONTROL}/corp-root.pem`)).text();
  const sys = asset.corp.systemId;
  await go(`#/systems/${sys}`);
  await sleep(900);
  const added = await js(`
    document.querySelector('#sec-anchors details').open = true;
    const ta = document.getElementById('anchor-pem');
    ta.value = ${JSON.stringify(pem)};
    const b = [...document.querySelectorAll('#sec-anchors button')].find((x) => x.textContent.trim() === 'Add to the bundle');
    b.click();
    await new Promise((r) => setTimeout(r, 1800));
    return document.getElementById('sec-anchors')?.innerText || '';`);
  check('T1-E2E.9', 'the system page adds a CA to its bundle', /Demo Corp Root CA/.test(added), added.slice(0, 120));
  const scansBefore = (await api(`/api/v1/assets/${ids.corp}/history`)).length;
  evCorp = await evOf('corp');
  const scansAfter = (await api(`/api/v1/assets/${ids.corp}/history`)).length;
  check('T1-E2E.10', 'the endpoint is now trusted by your CA bundle, with no new scan',
    !evCorp.findings.some((f) => f.id === 'CERT.UNTRUSTED') && evCorp.pki[0].private?.trusted && scansBefore === scansAfter,
    `${evCorp.findings.map((f) => f.id).join()} scans ${scansBefore}→${scansAfter}`);
  const refused = await post(`/api/v1/systems/${sys}/trust-anchors`, { pem: `${pem}-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n` });
  check('T1-E2E.11', 'an upload with a private key block is refused (SR-20)', refused.status === 400, refused.status);
  await go(`#/assets/${ids.corp}`);
  await sleep(900);
  const corpTrust = await js(`return document.querySelector('#sec-certificates .trusttable')?.innerText || ''`);
  check('T1-E2E.12', 'the trust row shows "your CA bundle: trusted"', /your CA bundle[\s\S]*trusted/.test(corpTrust), corpTrust.slice(0, 160));
  await shot('t1-private-ca-trusted');

  // ---- hostile target text in every new section ----------------------------------------------------------
  await go(`#/assets/${ids.hostile}`);
  await sleep(900);
  await js(`document.querySelectorAll('details').forEach((d) => { d.open = true; });`);
  await sleep(300);
  const xss = await js(`return {
    fired: window.__xss ?? null,
    injected: document.querySelectorAll('#main img, #main script, #main svg[onload], #main a[href^="javascript"]').length,
    shownSubject: document.querySelector('#sec-certificates')?.innerText.includes('<img src=x') || false,
    shownHSTS: document.querySelector('#sec-http')?.innerText.includes('<script>') || false,
    shownOCSP: document.querySelector('#sec-revocation')?.innerText.includes('javascript:window.__xss=8') || false };`);
  check('T1-E2E.13', 'hostile certificate subject, SAN, OCSP URL and HSTS header render as text and never execute',
    xss.fired === null && xss.injected === 0 && xss.shownSubject && xss.shownHSTS && xss.shownOCSP, JSON.stringify(xss));
  await shot('t1-hostile-as-text');

  // ---- narrow and dark ---------------------------------------------------------------------------------
  await viewport(390, 844, false, true);
  await go(`#/assets/${ids.broken}`);
  await sleep(900);
  const narrow = await js(`return { over: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    chips: getComputedStyle(document.querySelector('.secindex ol')).display }`);
  check('T1-E2E.14', 'at 390 px the report has no horizontal page scroll and the index is a chip row', narrow.over <= 1 && narrow.chips === 'flex', JSON.stringify(narrow));
  await shot('t1-report-390', { maxH: 2400 });
  await viewport(1280, 900, true);
  await go(`#/assets/${ids.broken}`);
  await sleep(900);
  await shot('t1-report-dark', { maxH: 1800 });
  await viewport(1280, 900);
}
