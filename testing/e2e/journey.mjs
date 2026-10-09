// End-to-end user journey, driven through a real browser (Edge/Chrome over the
// DevTools protocol), with screenshots and assertions. No dependencies: Node 22+.
//
//   cipherhorizon serve --allow-loopback --db e2e.db --addr 127.0.0.1:8090     (fresh database)
//   demo-targets                                                            (fresh process)
//   node testing/e2e/journey.mjs [--base http://127.0.0.1:8090] [--out DIR] [--browser PATH]
//
// It exercises PRD-001 end to end: add assets (single and bulk), scan, watch progress,
// cancel, read PQC readiness, compare history, upload a host CBOM, and check the
// hostile-name and layout cases. It writes NN-name.png files and results.json.
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { estatePhase } from './estate-phase.mjs';
import { authFetch as fetch } from './authfetch.mjs';
import { firstRun, authPhase } from './auth-phase.mjs';
import { t1Phase } from './t1-phase.mjs';
import { launchPhase } from './launch-phase.mjs';

const arg = (name, def) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : def; };
const BASE = arg('base', 'http://127.0.0.1:8090');
const OUT = arg('out', 'artifacts/screenshots');
const CONTROL = arg('control', 'http://127.0.0.1:9447');
const BROWSER = arg('browser', [
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/microsoft-edge',
].find(existsSync));
if (!BROWSER) { console.error('no Chromium-based browser found; pass --browser PATH'); process.exit(2); }
mkdirSync(OUT, { recursive: true });

const results = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function check(id, description, ok, detail = '') {
  results.push({ id, description, ok: !!ok, detail: String(detail) });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${id}  ${description}${ok ? '' : `  -- ${detail}`}`);
}

// ---- a minimal DevTools client ------------------------------------------------------------------

const port = 9333 + Math.floor(Math.random() * 500);
const profile = mkdtempSync(join(tmpdir(), 'cbom-e2e-'));
const proc = spawn(BROWSER, ['--headless=new', '--disable-gpu', '--hide-scrollbars', `--remote-debugging-port=${port}`,
  `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', '--window-size=1280,900',
  ...(process.env.CI ? ['--no-sandbox'] : []), 'about:blank'], { stdio: 'ignore' });
let ws, seq = 0;
const pending = new Map();
const consoleErrors = [];

async function connect() {
  for (let i = 0; i < 100; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      const page = list.find((t) => t.type === 'page');
      if (page) { ws = new WebSocket(page.webSocketDebuggerUrl); break; }
    } catch { /* browser still starting */ }
    await sleep(150);
  }
  if (!ws) throw new Error('could not reach the browser');
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  ws.onmessage = (m) => {
    const d = JSON.parse(m.data);
    if (d.id && pending.has(d.id)) { const { res, rej } = pending.get(d.id); pending.delete(d.id); d.error ? rej(new Error(d.error.message)) : res(d.result); return; }
    if (d.method === 'Runtime.exceptionThrown') consoleErrors.push(d.params.exceptionDetails.text + ' ' + (d.params.exceptionDetails.exception?.description || ''));
    if (d.method === 'Runtime.consoleAPICalled' && d.params.type === 'error') consoleErrors.push(d.params.args.map((a) => a.value ?? a.description).join(' '));
    if (d.method === 'Log.entryAdded' && d.params.entry.level === 'error' && !/favicon/.test(d.params.entry.url || '')) consoleErrors.push(d.params.entry.text + ' ' + (d.params.entry.url || ''));
  };
}
const send = (method, params = {}) => new Promise((res, rej) => { const id = ++seq; pending.set(id, { res, rej }); ws.send(JSON.stringify({ id, method, params })); });

async function js(expr) {
  const r = await send('Runtime.evaluate', { expression: `(async () => { ${expr} })()`, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(`page error: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}`);
  return r.result.value;
}
async function viewport(width, height = 900, dark = false, mobile = false) {
  await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile });
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: dark ? 'dark' : 'light' }] });
}
async function go(hash) {
  await send('Page.navigate', { url: `${BASE}/${hash}` });
  await sleep(900);
}
let shotN = 0;
async function shot(name, { full = true, maxH = 2600 } = {}) {
  let clip;
  if (full) {
    const m = await send('Page.getLayoutMetrics');
    const w = Math.ceil(m.cssContentSize.width), h = Math.min(Math.ceil(m.cssContentSize.height), maxH);
    clip = { x: 0, y: 0, width: w, height: h, scale: 1 };
  }
  const r = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: full, ...(clip ? { clip } : {}) });
  const file = `${String(++shotN).padStart(2, '0')}-${name}.png`;
  writeFileSync(join(OUT, file), Buffer.from(r.data, 'base64'));
  return file;
}
const api = async (path, opts) => (await fetch(`${BASE}${path}`, opts)).json();
const waitFor = async (fn, ms = 60000, every = 300) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { try { const v = await fn(); if (v) return v; } catch { /* keep trying */ } await sleep(every); }
  return null;
};
const location_is_list = (h) => h === '#/assets' || h === '#/endpoints';
const clickText = (text, scope = 'document') => js(`
  const b = [...${scope}.querySelectorAll('button, a')].find(x => x.textContent.trim() === ${JSON.stringify(text)});
  if (!b) return false; b.click(); return true;`);

// ---- the journey --------------------------------------------------------------------------------------

async function main() {
  await connect();
  await send('Page.enable'); await send('Runtime.enable'); await send('Log.enable');
  await viewport(1280, 900);

  // J0 (ADR-0018): first-run setup through the gate; everything after runs signed in.
  await firstRun({ check, js, go, sleep, shot });

  // J1 (UX-DESIGN-005): the first screen is the Overview with the scan box on top; one action
  // (type an address, press Enter) gives a report; a bad address is refused inline.
  await go('#/');
  const menu = await js(`return [...document.querySelectorAll('#nav a')].map((a) => a.innerText.trim().replace(/\\s+\\d+$/, ''))`);
  const navMeta = await js(`return { groups: [...document.querySelectorAll('#nav .navgroup')].map((g) => g.textContent.trim()), scan: document.getElementById('nav-scan')?.textContent.trim() || '' }`);
  check('F-M2', 'the menu is Overview, then Results (Endpoints, Machines, Findings, Inventory) and Plan & share (Systems, Reports), under a Scan a URL button (UX-DESIGN-005)',
    menu.join() === 'Overview,Endpoints,Machines,Findings,Inventory,Systems,Reports' && navMeta.groups.join('|') === 'Results|Plan & share' && navMeta.scan === 'Scan a URL',
    JSON.stringify({ menu, navMeta }));
  const hero = await js(`return { h1: document.querySelector('main h1')?.innerText || '', input: !!document.getElementById('scan-target'), focused: document.activeElement?.id || '' }`);
  check('E2E-F.0', 'the first screen is a scan box, focused', /Scan an endpoint for post.quantum readiness/.test(hero.h1) && hero.input && hero.focused === 'scan-target', JSON.stringify(hero));
  await shot('first-run-scan');
  const enter = async () => {
    await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: String.fromCharCode(13) });
    await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
  };
  await js(`const i = document.getElementById('scan-target'); i.focus(); i.value = 'not a valid host!!';`);
  await enter();
  await sleep(700);
  const inlineErr = await js(`const e = document.querySelector('.scan-error'); return e && !e.hidden ? e.innerText : ''`);
  check('E2E-F.2', 'a target the server refuses is explained under the input, not in a dialog', inlineErr.length > 0 && !(await js(`return !!document.querySelector('.modal')`)), inlineErr);
  await js(`const i = document.getElementById('scan-target'); i.focus(); i.value = '127.0.0.1:9448';`);
  await enter();
  const landed = await waitFor(async () => { const h = await js(`return location.hash`); return /^#\/endpoints\/\d+/.test(h) ? h : null; }, 10000, 200);
  const firstReport = await waitFor(async () => {
    const r = await js(`return { strip: !!document.querySelector('.sumstrip'), fix: !!document.querySelector('#fix'), h1: document.querySelector('main h1')?.innerText || '' }`);
    return r.strip && r.fix ? r : null;
  }, 60000, 500);
  check('F-M1', 'from an empty install, typing an address and pressing Enter gives its report', !!landed && !!firstReport, `${landed} ${JSON.stringify(firstReport)}`);
  await shot('first-report');

  // Add data: the three inputs in one dialog (REQ-INV-6); the collector how-to is one of them.
  await go('#/');
  await clickText('Import a CBOM');
  await sleep(300);
  const tiles = await js(`return [...document.querySelectorAll('.modal .adddata-tile h3')].map((x) => x.innerText)`);
  check('E2E-12.1', 'Add data offers the three ways in: scan an endpoint, inventory a machine, import a CBOM',
    tiles.join('|') === 'Scan an endpoint|Inventory a machine|Import a CBOM', tiles.join('|'));
  await clickText('Show me how', "document.querySelector('.modal')");
  await sleep(300);
  const howto = await js(`const m = document.querySelector('.modal'); return { text: m ? m.innerText : '', cmds: m ? m.querySelectorAll('.cmdblock').length : 0, copies: m ? m.querySelectorAll('.cmdblock .copybtn').length : 0 }`);
  check('E2E-12.2', 'the how-to gives the PowerShell and shell inventory scripts with copyable commands, and no program to download',
    howto.cmds >= 2 && howto.copies === howto.cmds && /cipherhorizon-inventory\.ps1/.test(howto.text) && /cipherhorizon-inventory\.sh/.test(howto.text) && !/collector\.exe/.test(howto.text), JSON.stringify(howto).slice(0, 160));
  await shot('how-to-collect-dialog', { full: false });
  await clickText('Close', "document.querySelector('.modal')");
  await sleep(300);

  // "Scan many endpoints" opens the bulk dialog, which J2/J3 exercise.
  await clickText('Scan many endpoints');
  await sleep(250);
  const dlg = await js(`return document.querySelector('.modal')?.getAttribute('aria-label') || document.querySelector('.modal h2')?.innerText || ''`);
  check('E2E-01.0', '"Scan many endpoints" opens the add-endpoints dialog', /Add endpoints/i.test(dlg), dlg);
  await js(`document.querySelector('.modal .icon-btn')?.click()`);
  await sleep(200);

  // J2: add a single endpoint (AC-01.1) with a name and tags; a bad one shows a clear error (AC-01.3).
  await clickText('Scan many endpoints');
  await sleep(250);
  await shot('add-endpoint-dialog', { full: false });
  await js(`document.getElementById('add-target').value = 'not a valid host!!'; document.querySelector('.modal form').requestSubmit();`);
  await sleep(500);
  const err = await js(`return document.querySelector('.modal .callout.bad')?.innerText || ''`);
  check('E2E-01.4', 'an invalid target is refused with a message', err.length > 0, err);
  await shot('add-endpoint-invalid', { full: false });
  await js(`document.getElementById('add-target').value = '127.0.0.1:9440'; document.getElementById('add-name').value = 'modern-hybrid'; document.getElementById('add-tags').value = 'demo, web'; document.getElementById('add-tags').focus();`);
  // A real Enter key press (with its character), as a person would type it, must submit the form.
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: String.fromCharCode(13) });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
  await sleep(800);
  let assets = await api('/api/v1/assets?kind=tls-endpoint');
  const mh = assets.find((a) => a.port === 9440);
  check('E2E-01.1', 'a single endpoint can be added with name and tags', assets.length === 2 && mh && mh.name === 'modern-hybrid' && mh.tags.join() === 'demo,web', JSON.stringify(assets.map((a) => a.name)));
  // Adding from the dialog lands on Endpoints, which has the same button.
  await go('#/endpoints');

  // J3: bulk add (AC-01.2, AC-01.4): comments ignored, duplicates and bad lines reported, good lines added.
  await clickText('Add endpoints');
  await sleep(250);
  await clickText('Paste a list');
  await sleep(150);
  await js(`document.getElementById('add-list').value = ${JSON.stringify(['# the demo targets', '127.0.0.1:9441', '127.0.0.1:9442', '127.0.0.1:9443', '127.0.0.1:9444', '127.0.0.1:9445', '127.0.0.1:9446', '127.0.0.1:9440', 'not a host!!', 'http://169.254.169.254/latest'].join('\n'))};
    document.querySelector('.modal form').requestSubmit();`);
  await sleep(900);
  const bulk = await js(`return document.querySelector('.modal [role=status]')?.innerText || ''`);
  check('E2E-01.2', 'bulk add reports 6 added, 1 duplicate, 2 invalid', /6 added, 1 already present, 2 invalid/.test(bulk), bulk);
  await shot('add-bulk-result', { full: false });
  await js(`document.querySelector('.modal .icon-btn').click()`);
  assets = await api('/api/v1/assets?kind=tls-endpoint');
  check('E2E-11.4', 'the metadata address was not added', !assets.some((a) => a.host === '169.254.169.254') && assets.length === 8, assets.length);

  // Give the friendly names to the rest so screenshots read well (also exercises Edit, US-01).
  const names = { 9441: 'classical-tls13', 9442: 'legacy-tls12', 9443: 'terrible-legacy', 9444: 'dead-port', 9445: 'pq-toggle', 9446: 'slow-hybrid' };
  for (const a of assets) {
    if (!names[a.port]) continue;
    await fetch(`${BASE}/api/v1/assets/${a.id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'cipherhorizon' }, body: JSON.stringify({ name: names[a.port] }) });
  }
  const byPort = Object.fromEntries((await api('/api/v1/assets?kind=tls-endpoint')).map((a) => [a.port, a]));
  await go('#/assets');
  await shot('endpoints-not-scanned');

  // J4: scan everything (US-02). The slow target lets us watch a scan run.
  await clickText('Scan all');
  await sleep(2500);
  await shot('endpoints-scanning');
  const running = await js(`return [...document.querySelectorAll('.pill')].map(p => p.textContent)`);
  check('E2E-02.1', 'scans start and show as Queued/Running in the list', running.some((t) => /Running|Queued/.test(t)), running.join());

  await go(`#/assets/${byPort[9446].id}`);
  await sleep(1500);
  await shot('scan-progress');
  const prog = await js(`return { text: document.querySelector('.scanpanel')?.innerText || '', steps: document.querySelectorAll('.step').length, pct: document.querySelector('.scanpanel [role=progressbar]')?.getAttribute('aria-valuenow') }`);
  check('E2E-02.2', 'progress panel shows percent, connections, stages and a log', prog.steps === 5 && /connections/.test(prog.text) && Number(prog.pct) >= 0, JSON.stringify(prog).slice(0, 160));

  // Cancel it (AC-02.5).
  await clickText('Cancel scan');
  await sleep(1500);
  const canceled = (await api(`/api/v1/scans?assetId=${byPort[9446].id}&limit=1`))[0];
  check('E2E-02.5', 'a running scan can be canceled from the page', canceled.status === 'canceled', canceled.status);
  const detail = await api(`/api/v1/scans/${canceled.id}`);
  check('E2E-02.5b', 'the scan log ends at the cancellation', detail.events.at(-1).message === 'canceled by user', detail.events.at(-1).message);
  await shot('scan-canceled');

  // Wait for the rest to finish.
  const finished = await waitFor(async () => {
    const list = await api('/api/v1/assets?kind=tls-endpoint');
    return list.filter((a) => a.id !== byPort[9446].id).every((a) => a.latest && ['done', 'failed'].includes(a.latest.status)) ? list : null;
  }, 90000);
  check('E2E-02.3', 'all scans reach a final state', !!finished);
  const by = Object.fromEntries((finished || []).map((a) => [a.port, a]));

  // J5: readiness on the fleet (US-03..05).
  const expectLevel = { 9440: 3, 9441: 1, 9442: 0, 9443: 0 };
  for (const [p, lv] of Object.entries(expectLevel)) {
    check(`E2E-04.4.${p}`, `endpoint :${p} reads L${lv}`, by[p]?.lastDone?.readinessLevel === lv, by[p]?.lastDone?.readinessLevel);
  }
  check('E2E-05.3', 'the SSLv3 endpoint has TLS hygiene Broken, and a sound TLS 1.2 one is not', by[9443]?.lastDone?.band === 'Broken' && by[9442]?.lastDone?.band !== 'Broken',
    `${by[9443]?.lastDone?.band} ${by[9443]?.lastDone?.score} / ${by[9442]?.lastDone?.band} ${by[9442]?.lastDone?.score}`);
  const hyg = (await api(`/api/v1/scans/${by[9443].lastDone.id}/evaluation`)).hygiene;
  const hygFindings = (await api(`/api/v1/scans/${by[9443].lastDone.id}/evaluation`)).findings;
  const sum = hyg.deductions.reduce((n, d) => n + d.points, 0);
  check('E2E-05.3b', 'every point taken off traces to a finding, and the total adds up',
    hyg.deductions.length > 0 && hyg.deductions.every((d) => hygFindings.some((f) => f.id === d.finding && f.severity === d.severity)) &&
    hyg.score === (hyg.ceiling ? hyg.ceiling.score : Math.max(0, 100 - sum)), `${hyg.deductions.length} deductions, score ${hyg.score}`);
  check('E2E-02.4', 'the dead port fails with a readable reason', by[9444]?.latest?.status === 'failed' && /no response|refused|connect/i.test(by[9444].latest.error), by[9444]?.latest?.error);
  await go(`#/endpoints/${by[9444].id}`);
  await sleep(900);
  const dead = await js(`return { card: document.querySelector('.failcard')?.innerText || '', chart: /Readiness over time/.test(document.querySelector('main').innerText),
    retry: [...document.querySelectorAll('.failcard button')].some((b) => b.textContent.trim() === 'Scan again') }`);
  check('E2E-02.4b', 'a failed endpoint shows one card that says why in plain words, with Scan again, and no empty charts',
    /We could not scan/.test(dead.card) && /Nothing accepted a connection/.test(dead.card) && dead.retry && !dead.chart, JSON.stringify(dead).slice(0, 200));
  await shot('failed-endpoint');
  check('E2E-04.1', 'L0/L1 endpoints are flagged exposed to harvest-now-decrypt-later', by[9441]?.lastDone?.hndlExposed && by[9442]?.lastDone?.hndlExposed && !by[9440]?.lastDone?.hndlExposed);

  await go('#/assets');
  await sleep(600);
  await shot('endpoints-results');
  await go('#/overview');
  await sleep(900);
  await shot('dashboard');

  // Per-endpoint pages.
  for (const [port, tag] of [[9440, 'modern-hybrid-L3'], [9441, 'classical-tls13-L1'], [9442, 'legacy-tls12-L0'], [9443, 'terrible-legacy-broken']]) {
    await go(`#/assets/${by[port].id}`);
    await sleep(700);
    const head = await js(`return document.querySelector('.bigLevel')?.innerText || ''`);
    check(`E2E-04.1.${port}`, `overview of :${port} shows its readiness level`, head.includes(`L${expectLevel[port]}`), head);
    await shot(`asset-${tag}-overview`);
  }
  await go(`#/assets/${by[9443].id}`);
  await sleep(500);
  await shot('asset-terrible-legacy-report');
  // Action items: each finding once, in plain words (PRD-006 REQ-RV-2).
  const fnd = await js(`const rows = [...document.querySelectorAll('#fix .action')];
    const groups = [...document.querySelectorAll('#fix .action-group')];
    return { rows: rows.length, todo: rows.filter((r) => /What to do:/.test(r.innerText)).length,
      groups: groups.length, groupWhy: groups.filter((g) => /Why it matters:/.test(g.querySelector('.action-group-head')?.innerText || '')).length,
      whys: groups.map((g) => g.querySelector('.action-why')?.textContent),
      titles: rows.map((r) => r.querySelector('.action-title').textContent) }`);
  check('E2E-05.2', 'action items list each finding once with what to do, grouped so each reason (why it matters) is said once',
    fnd.rows > 0 && fnd.todo === fnd.rows && fnd.groups > 0 && fnd.groupWhy === fnd.groups && new Set(fnd.whys).size === fnd.whys.length
    && new Set(fnd.titles).size === fnd.titles.length, JSON.stringify(fnd).slice(0, 200));
  await shot('asset-terrible-legacy-findings');
  await js(`[...document.querySelectorAll('.tab')].find((t) => t.textContent === 'Weaknesses').click()`);
  await sleep(400);
  const vulns = await js(`return document.querySelector('.report.weaknesses')?.innerText || ''`);
  check('E2E-05.4', 'Weaknesses names the possible attacks and the ones not tested by design',
    /POODLE[\s\S]*Possible/.test(vulns) && /Heartbleed[\s\S]*Not tested/.test(vulns), vulns.slice(0, 160));
  const cites = await js(`const found = [...document.querySelectorAll('.weakcard .issue')]; found.forEach((r) => { r.querySelector('details').open = true; });
    const passed = [...document.querySelectorAll('.chk-passed .clean')].map((li) => li.innerText);
    const btn = (k) => document.querySelector('.chkfilter-btn[data-show="' + k + '"]');
    const shown = (sel) => [...document.querySelectorAll(sel)].filter((e) => e.offsetParent !== null).length;
    btn('found').click();
    const onlyFound = { issues: shown('.weakcard .issue'), passed: shown('.chk-passed .clean') };
    btn('passed').click();
    const onlyPassed = { issues: shown('.weakcard .issue'), passed: shown('.chk-passed .clean') };
    btn('all').click();
    return { found: found.length, cited: found.filter((r) => r.querySelector('.cites a')).length, passed: passed.length,
      worded: passed.filter((t) => !/not found/.test(t)).length, toggles: document.querySelectorAll('.weakcard .issue-toggle').length, onlyFound, onlyPassed }`);
  check('E2E-05.5', 'Weaknesses lists every check: found ones with their sources and a Details toggle, passed ones saying what was confirmed (PRD-006 REQ-RV-4)',
    cites.found > 0 && cites.cited === cites.found && cites.toggles === cites.found && cites.passed > 10 && cites.worded === cites.passed, JSON.stringify(cites));
  check('E2E-05.6', 'the Found / Passed filter shows only that kind of check',
    cites.onlyFound.issues === cites.found && cites.onlyFound.passed === 0 && cites.onlyPassed.issues === 0 && cites.onlyPassed.passed === cites.passed, JSON.stringify(cites));
  await go(`#/assets/${by[9440].id}`);
  await sleep(500);
  await shot('asset-modern-hybrid-report');

  // J6: history and change over time (US-07): flip the toggle target to hybrid and rescan.
  const t = by[9445];
  check('E2E-07.pre', 'the toggle target starts classical (L1)', t.lastDone.readinessLevel === 1, t.lastDone.readinessLevel);
  const flip = await fetch(`${CONTROL}/pq/on`, { method: 'POST' });
  check('E2E-07.setup', 'operator enables hybrid key exchange on the target', flip.ok, flip.status);
  await go(`#/assets/${t.id}`);
  await sleep(600);
  await clickText('Scan again');
  const after = await waitFor(async () => { const a = await api(`/api/v1/assets/${t.id}`); return a.latest?.status === 'done' && a.lastDone.id !== t.lastDone.id ? a : null; }, 60000);
  check('E2E-07.1', 'a rescan runs and records a second result', !!after && after.lastDone.readinessLevel === 3, after?.lastDone?.readinessLevel);
  await go(`#/assets/${t.id}?tab=history`);
  await sleep(500);
  // Adding from the estate scans at once (WP-8), so an endpoint may already have more than one result.
  await js(`[...document.querySelectorAll('button, a')].find((x) => /^History \(\d+\)$/.test(x.textContent.trim()))?.click()`);
  await sleep(900);
  const hist = await js(`return { dots: document.querySelectorAll('svg.chart circle.dot').length, diff: document.body.innerText.match(/\\d+ change\\(s\\)[^\\n]*/)?.[0] || '', better: [...document.querySelectorAll('.impact')].map(x => x.textContent).join() }`);
  check('E2E-07.3', 'history chart shows the scans and the diff shows the improvement', hist.dots >= 2 && /better/.test(hist.diff) && /better/.test(hist.better), JSON.stringify(hist));
  await shot('asset-history-and-diff');
  // Open the older scan read-only (AC-07.4).
  const older = (await api(`/api/v1/assets/${t.id}/history`))[0];
  await go(`#/assets/${t.id}?scan=${older.scanId}`);
  await sleep(800);
  const viewing = await js(`return { banner: document.querySelector('.viewing')?.innerText || '', level: document.querySelector('.bigLevel')?.innerText || '' }`);
  check('E2E-07.4', 'a past scan opens read-only with its own level (L1)', /past scan/i.test(viewing.banner) && viewing.level.includes('L1'), JSON.stringify(viewing));
  await shot('asset-past-scan-readonly');

  // J7: scans list, schedule, filter, export.
  await go('#/scans');
  await sleep(700);
  await shot('scans-list');
  await go(`#/assets/${by[9440].id}`);
  await sleep(500);
  await js(`const s = document.querySelector('select[aria-label="Automatic rescans"]'); s.value = '86400'; s.dispatchEvent(new Event('change'));`);
  await sleep(600);
  const sa = await api(`/api/v1/assets/${by[9440].id}`);
  check('E2E-08.1', 'a rescan schedule can be set (every day) and a next run is planned', sa.intervalSeconds === 86400 && !!sa.nextScanAt, sa.nextScanAt);
  const csv = await (await fetch(`${BASE}/api/v1/export/assets.csv`)).text();
  check('E2E-09.1', 'endpoints export as CSV with readiness and TLS hygiene columns', /pqc_level/.test(csv.split('\n')[0]) && /hygiene_band/.test(csv.split('\n')[0]) && /hygiene_score/.test(csv.split('\n')[0]) &&csv.split('\n').length > 7, csv.split('\n')[0]);

  // J8: hostile names never execute (AC-11.6).
  await go('#/assets');
  await clickText('Add endpoints');
  await sleep(250);
  await js(`document.getElementById('add-target').value = '127.0.0.2:9441';
    document.getElementById('add-name').value = '<img src=x onerror=window.__xss=1><script>window.__xss=2<\\/script>';
    document.getElementById('add-tags').value = '"><svg onload=window.__xss=3>';
    document.querySelector('.modal form').requestSubmit();`);
  await sleep(900);
  const xss = await js(`return { fired: window.__xss ?? null, injected: document.querySelectorAll('#main img, #main script, #main svg[onload]').length, shown: !!([...document.querySelectorAll('#main a')].find(a => a.textContent.includes('<img'))) }`);
  check('E2E-11.6', 'a hostile endpoint name is shown as text and never executes', xss.fired === null && xss.injected === 0 && xss.shown, JSON.stringify(xss));
  await shot('hostile-name-as-text');
  const hostile = (await api('/api/v1/assets?kind=tls-endpoint')).find((a) => a.host === '127.0.0.2');

  // AC-01.5: edit and delete from the endpoint page, with a confirmation before anything is lost.
  await go(`#/assets/${hostile.id}`);
  await sleep(600);
  await js(`document.querySelector('.more-menu').open = true`);
  await clickText('Edit name, tags, notes and STARTTLS');
  await sleep(250);
  await js(`document.getElementById('e-name').value = 'renamed in the UI'; document.getElementById('e-notes').value = 'edited by the journey'; document.querySelector('.modal form').requestSubmit();`);
  await sleep(700);
  const edited = await api(`/api/v1/assets/${hostile.id}`);
  check('E2E-01.5a', 'name and notes can be edited from the endpoint page (More menu)', edited.name === 'renamed in the UI' && edited.notes === 'edited by the journey', edited.name);
  await clickText('Delete this endpoint');
  await sleep(250);
  await shot('delete-confirmation', { full: false });
  await clickText('Cancel', "document.querySelector('.modal')");
  await sleep(250);
  check('E2E-01.5b', 'canceling the confirmation keeps the endpoint', (await fetch(`${BASE}/api/v1/assets/${hostile.id}`)).status === 200);
  await clickText('Delete this endpoint');
  await sleep(250);
  await clickText('Delete', "document.querySelector('.modal')");
  await sleep(800);
  check('E2E-01.5c', 'confirming deletes the endpoint and returns to the list', (await fetch(`${BASE}/api/v1/assets/${hostile.id}`)).status === 404 && location_is_list(await js(`return location.hash`)));

  // J9: machines (US-09): upload a CBOM through the file input, from Machines.
  await go('#/machines');
  await sleep(500);
  await shot('hosts-empty');
  const hostsEmpty = await js(`return document.querySelector('main').innerText`);
  check('E2E-12.3', 'the empty Machines page teaches the three steps with the exact command', /Inventory your first machine/.test(hostsEmpty) && /cipherhorizon-inventory\.sh/.test(hostsEmpty) && /Automate the upload/.test(hostsEmpty), hostsEmpty.slice(0, 100));
  const bom = { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, metadata: { timestamp: '2026-09-21T10:00:00Z', component: { 'bom-ref': 'host:web-01', type: 'device', name: 'web-01' } },
    components: [
      { 'bom-ref': 'crypto/rsa', type: 'cryptographic-asset', name: 'RSA', cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'pke' }, oid: '1.2.840.113549.1.1.1' } },
      { 'bom-ref': 'crypto/sha256', type: 'cryptographic-asset', name: 'SHA-256', cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'hash' }, oid: '2.16.840.1.101.3.4.2.1' } },
      { 'bom-ref': 'pkg/libgcrypt20', type: 'library', name: 'libgcrypt20', version: '1.10.3' }],
    dependencies: [{ ref: 'pkg/libgcrypt20', provides: ['crypto/rsa', 'crypto/sha256'] }] };
  await clickText('Upload results');
  await sleep(250);
  await shot('host-upload-dialog', { full: false });
  await js(`const dt = new DataTransfer(); dt.items.add(new File([${JSON.stringify(JSON.stringify(bom))}], 'web-01.cbom.json', { type: 'application/json' }));
    document.getElementById('cbom-file').files = dt.files; document.querySelector('.modal form').requestSubmit();`);
  await sleep(1000);
  const host = await js(`return { hash: location.hash, text: document.querySelector('main').innerText }`);
  check('E2E-10.1', 'a CBOM uploads and opens the host page with verdicts', /#\/machines\/\d+/.test(host.hash) && /quantum-vulnerable/.test(host.text) && /quantum-safe/.test(host.text), host.hash);
  check('E2E-10.2', 'the host page states capability is not use', /Capability, not use/.test(host.text));
  check('E2E-10.3', 'the package is shown as providing the algorithms', /libgcrypt20/.test(host.text));
  check('E2E-12.4', 'a CBOM that records no coverage is shown as Not recorded, never as complete', /Inventory coverage/.test(host.text) && /Not recorded/.test(host.text) && !/Full access/.test(host.text), host.text.slice(0, 80));
  await shot('host-detail');
  const badUpload = await fetch(`${BASE}/api/v1/hosts/ingest`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'cipherhorizon' }, body: '{"hello":"world"}' });
  check('E2E-10.4', 'a non-CBOM upload is refused with 400', badUpload.status === 400, badUpload.status);
  await go('#/inventory/sources');
  await sleep(500);
  await shot('hosts-list');

  // J9b: a collector-style CBOM that carries its coverage (privilege, sensors, blind spots).
  const bom2 = JSON.parse(JSON.stringify(bom));
  bom2.metadata.component = { 'bom-ref': 'host:db-02', type: 'device', name: 'db-02' };
  bom2.metadata.properties = [
    { name: 'cipherhorizon:privilege-tier', value: 'user' },
    { name: 'cipherhorizon:host-os', value: 'windows 10.0.26200' },
    { name: 'cipherhorizon:coverage-note', value: '129 location(s) could not be read for lack of permission, so results may be incomplete.' },
    { name: 'cipherhorizon:coverage', value: 'sensor=pe-files status=partial reason=permission denied=129 scope=crypto-library files under Program Files' },
    { name: 'cipherhorizon:coverage', value: 'sensor=windows-cng status=complete scope=Windows CNG algorithm registry and providers' },
    { name: 'cipherhorizon:not-seen', value: 'certificates, configuration and key material (not collected by this version)' }];
  // A legacy algorithm with its cited status, as the native Windows sensor writes it.
  bom2.components.push({ 'bom-ref': 'crypto/md5', type: 'cryptographic-asset', name: 'MD5',
    cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'hash' }, oid: '1.2.840.113549.2.5' },
    properties: [{ name: 'cipherhorizon:classical-status', value: 'has updated security considerations because of weaknesses' },
      { name: 'cipherhorizon:classical-basis', value: 'RFC 6151, Updated Security Considerations for the MD5 Message-Digest (https://www.rfc-editor.org/rfc/rfc6151)' }] });
  bom2.dependencies[0].provides.push('crypto/md5');
  const up2 = await fetch(`${BASE}/api/v1/hosts/ingest`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'cipherhorizon' }, body: JSON.stringify(bom2) });
  const up2j = await up2.json();
  await go(`#/hosts/${up2j.asset.id}`);
  await sleep(700);
  const cov = await js(`return document.querySelector('.coverage')?.innerText || ''`);
  check('E2E-12.5', 'the host page shows privilege, system, what was not readable and what cannot be seen',
    /Limited access/.test(cov) && /Standard user/.test(cov) && /Windows 10\.0\.26200/.test(cov) && /129 location/.test(cov) && /cannot see/.test(cov) && /full rights/.test(cov), cov.slice(0, 160));
  await shot('host-coverage');
  const legacy = await js(`return document.querySelector('.legacy')?.innerText || ''`);
  check('E2E-13.1', 'retired or broken algorithms are listed with what the cited source says, apart from the quantum verdicts',
    /Retired or broken algorithms \(1\)/.test(legacy) && /MD5/.test(legacy) && /RFC 6151/.test(legacy) && /not quantum ones/.test(legacy), legacy.slice(0, 160));
  check('E2E-13.2', 'the native Windows sensor is named in plain words in the coverage table', /Windows cryptography \(CNG\)/.test(cov), cov.slice(0, 200));
  await shot('host-legacy-algorithms');
  await js(`document.querySelector('.coverage details summary').click()`);
  const unseen = await js(`return document.querySelector('.coverage details').innerText`);
  check('E2E-12.6', 'the blind spots open on demand', /certificates, configuration and key material/.test(unseen), unseen.slice(0, 80));
  const why = await js(`const d = document.querySelector('details.why'); const before = d.open; d.querySelector('summary').click(); return { before, after: d.open, text: d.innerText }`);
  check('E2E-12.7', 'the reason for a verdict is one click away, with its sources', why.before === false && why.after === true && /Matched by/.test(why.text), JSON.stringify(why).slice(0, 100));
  await go('#/machines');
  await sleep(600);
  const hostsList = await js(`return document.querySelector('main').innerText`);
  check('E2E-12.8', 'the Hosts list shows system and access for each machine', /Limited access/.test(hostsList) && /Not recorded/.test(hostsList) && /Windows 10\.0\.26200/.test(hostsList), hostsList.slice(0, 120));
  await clickText('Add a machine');
  await sleep(300);
  check('E2E-12.9', 'the collector how-to is reachable from a populated Hosts page', (await js(`return document.querySelectorAll('.modal .cmdblock').length`)) >= 2);
  await clickText('Close', "document.querySelector('.modal')");
  await sleep(300);

  // J9d (UX-DESIGN-005): each place checked for what it promises.
  await go('#/');
  await sleep(1200);
  const home = await js(`const rows = [...document.querySelectorAll('.recent-row')];
    const tiles = [...document.querySelectorAll('.statusband .stat')];
    return { rows: rows.length, verdicts: rows.filter((r) => r.querySelector('.lvbadge, .badge, .pill')).length, links: rows.every((r) => /^#[/]endpoints[/][0-9]+$/.test(r.getAttribute('href'))),
      tiles: tiles.map((t) => t.querySelector('.stat-label')?.textContent + '>' + t.getAttribute('href')), fix: document.querySelectorAll('.firstfix li').length,
      scale: [...document.querySelectorAll('.hero-scale .level-code')].map((x) => x.textContent).join('') }`);
  check('E2E-F.3', 'Overview lists the latest results, each with its verdict and a link to its report, and what to fix first', home.rows >= 1 && home.rows <= 6 && home.verdicts === home.rows && home.links && home.fix > 0, JSON.stringify(home).slice(0, 300));
  check('E2E-F.4', 'Overview has one status band with a figure per question, each opening its place, and the readiness scale L4 to L0 as the legend (DESIGN.md §8)',
    home.scale === 'L4L3L2L1L0' &&
    home.tiles.join('|') === 'Endpoints>#/endpoints|Machines>#/machines|Findings>#/findings|Post-quantum>#/endpoints|Inventory>#/inventory|Next certificate expiry>#/inventory/certificates', home.tiles.join('|'));
  await go('#/endpoints');
  await sleep(900);
  const reps = await js(`const rows = [...document.querySelectorAll('main tbody tr')];
    return { head: document.querySelector('main h1')?.textContent, tabs: [...document.querySelectorAll('.tabs .tab')].map((t) => t.textContent).join('|'), rows: rows.length,
      open: rows.filter((r) => /Open report/.test(r.innerText)).length, scanned: rows.filter((r) => /Hybrid|Not ready|Classical|ready/i.test(r.innerText)).length,
      findings: rows.map((r) => r.children[4]?.innerText || ''), actions: !!document.querySelector('.toolbar .toolbar-actions') }`);
  check('E2E-F.5', 'Endpoints lists every endpoint with Add, Scan all and Export beside the filter, and a Scan activity tab',
    reps.head === 'Endpoints' && reps.tabs === 'Endpoints|Scan activity' && reps.rows >= 5 && reps.actions, JSON.stringify(reps).slice(0, 300));
  check('E2E-R.4', 'a row has one way in (the row opens the report: no second Open report button), and its findings column names the worst severity or says No problems (UX-REVIEW-008 E1, E2)',
    reps.open === 0 && reps.findings.every((t) => t !== 'none') && reps.findings.some((t) => /\d+ (critical|high|medium|low)|No problems/.test(t)), JSON.stringify(reps.findings));
  const rowClick = await js(`const r = [...document.querySelectorAll('main tbody tr.rowlink')].find((x) => /L\\d/.test(x.innerText));
    r.querySelector('td:nth-child(5)').click(); await new Promise((ok) => setTimeout(ok, 600));
    return { hash: location.hash, crumbs: [...document.querySelectorAll('.crumbs li')].map((l) => l.textContent), lit: document.querySelector('#nav a[aria-current=page]')?.textContent.trim() }`);
  check('E2E-R.5', 'clicking anywhere on a row opens its report, which names its home (Endpoints) in a breadcrumb and in the menu',
    /^#\/endpoints\/\d+/.test(rowClick.hash) && rowClick.crumbs[0] === 'Endpoints' && rowClick.lit === 'Endpoints', JSON.stringify(rowClick));
  // Reports holds documents, not data (UX-DESIGN-005 principle 6).
  await go('#/reports');
  await sleep(1200);
  const docs = await js(`const t = document.querySelector('main').innerText;
    return { head: document.querySelector('main h1')?.textContent, sections: [...document.querySelectorAll('.reports-docs h2')].map((x) => x.textContent),
      epRows: document.querySelectorAll('.docs-table tbody tr').length, pdfButtons: [...document.querySelectorAll('.docs-table button')].filter((b) => b.textContent === 'Security').length,
      invPdf: [...document.querySelectorAll('.docrow button')].some((b) => b.textContent === 'Download PDF'), tiles: document.querySelectorAll('.fleet-tile').length }`);
  check('E2E-N.1', 'Reports lists documents: the inventory report and CBOM, a row of PDF reports and a CBOM per endpoint, machine CBOMs, CSV and standards exports; no data table of its own',
    docs.head === 'Reports' && docs.sections.join('|') === 'Your cryptographic inventory|Endpoint reports|Machine CBOMs|Spreadsheets and standards exports' && docs.pdfButtons >= 5 && docs.invPdf && docs.tiles === 0,
    JSON.stringify(docs));
  const pdf = await js(`const b = [...document.querySelectorAll('.docs-table button')].find((x) => x.textContent === 'Security');
    const orig = window.fetch; let got = null;
    window.fetch = async (...a) => { const r = await orig(...a); got = { url: String(a[0]), type: r.headers.get('content-type') }; return r; };
    b.click(); await new Promise((ok) => setTimeout(ok, 1500)); window.fetch = orig; return got;`);
  check('E2E-N.2', 'a document downloads in one click from Reports', !!pdf && /report\.pdf\?kind=full/.test(pdf.url) && /application\/pdf/.test(pdf.type), JSON.stringify(pdf));
  // The Scan a URL button works from any page and lands on the new report.
  await go('#/inventory');
  await sleep(700);
  await js(`document.getElementById('nav-scan').click()`);
  await sleep(300);
  const scanDlg = await js(`return { open: !!document.querySelector('.modal[aria-label="Scan a URL"]'), focused: document.activeElement?.id }`);
  await js(`const i = document.getElementById('scan-dialog-target'); i.value = '127.0.0.1:9440'; i.form.requestSubmit();`);
  const viaButton = await waitFor(async () => { const h = await js(`return location.hash`); return /^#\/endpoints\/\d+/.test(h) ? h : null; }, 8000, 200);
  check('E2E-N.3', 'Scan a URL opens a scan box from any page and lands on that endpoint\'s report', scanDlg.open && scanDlg.focused === 'scan-dialog-target' && viaButton === `#/endpoints/${by[9440].id}`,
    JSON.stringify({ scanDlg, viaButton }));
  await sleep(500);
  await go('#/findings');
  await sleep(1100);
  const fl = await js(`const g = [...document.querySelectorAll('details.fgroup')];
    const api = await (await fetch('/api/v1/findings', { headers: { 'X-Requested-With': 'cipherhorizon' } })).json();
    return { groups: g.length, closed: g.filter((d) => !d.open).length, findings: api.length,
      words: document.querySelector('main').innerText.split(/ +|\\n+/).filter(Boolean).length }`);
  check('E2E-F.12', 'fleet Findings is one closed line per problem, not one card per endpoint', fl.groups > 0 && fl.groups < fl.findings && fl.closed === fl.groups, JSON.stringify(fl));
  const lit = await js(`return document.querySelector('#nav a[aria-current=page]')?.textContent.trim()`);
  check('E2E-N.4', 'Findings is a place of its own in the menu', lit === 'Findings', lit);
  await shot('findings');
  await go(`#/machines/${(await api('/api/v1/hosts'))[0].id}`);
  await sleep(900);
  const mcr = await js(`return { crumbs: [...document.querySelectorAll('.crumbs li')].map((l) => l.textContent), lit: document.querySelector('#nav a[aria-current=page]')?.textContent.trim() }`);
  check('E2E-N.5', 'a machine\'s page names its home (Machines) in a breadcrumb and in the menu', mcr.crumbs[0] === 'Machines' && mcr.lit === 'Machines', JSON.stringify(mcr));
  await go(`#/endpoints/${by[9443].id}`);
  await sleep(1100);
  const rp = await js(`const top = (sel) => { const e = document.querySelector(sel); return e ? e.getBoundingClientRect().top : 1e9; };
    const head = [...document.querySelectorAll('.page-head button, .page-head summary')].map((b) => b.textContent.trim());
    const issues = [...document.querySelectorAll('#fix .action-title')].map((x) => x.textContent);
    const checks = document.querySelectorAll('#checks .check-row').length;
    const coverage = document.querySelector('.coverage-line')?.innerText || '';
    const tabs = [...document.querySelectorAll('.tabs .tab')].map((t) => t.textContent.split('(')[0].trim());
    const strip = top('.sumstrip') < innerHeight * 2, fix = top('#fix') < innerHeight * 2;
    const tab = (n) => [...document.querySelectorAll('.tab')].find((t) => t.textContent === n).click();
    tab('Configuration');
    await new Promise((r) => setTimeout(r, 400));
    const rows = [...document.querySelectorAll('.matrix .ver-row')];
    const matrix = { rows: rows.length, names: rows.map((r) => r.querySelector('.ver-name')?.textContent), opened: false, suites: 0,
      states: Object.fromEntries(rows.map((r) => [r.querySelector('.ver-name')?.textContent, r.querySelector('.vstate')?.textContent])),
      summary: document.querySelector('.ver-sum')?.textContent || '' };
    const on = document.querySelector('.matrix details.ver-row');
    if (on) { on.open = true; matrix.opened = true; matrix.suites = on.querySelectorAll('tbody tr').length; }
    const cards = [...document.querySelectorAll('.detcard')];
    const purposes = cards.map((c) => (c.querySelector('.purpose')?.textContent || '').trim().split(/ +/).length);
    const findingCards = document.querySelectorAll('.report.configuration .finding, .report.configuration .issue').length;
    const about = !!document.querySelector('#sec-details');
    tab('CBOM');
    await new Promise((r) => setTimeout(r, 1200));
    const cbom = { rows: document.querySelectorAll('.report.cbom tbody tr').length, counts: document.querySelectorAll('.cbom-count').length,
      dl: [...document.querySelectorAll('.report.cbom button')].map((b) => b.textContent) };
    return { strip, fix, issues, checks, coverage, tabs, head, matrix, details: cards.length, findingCards, maxPurpose: Math.max(...purposes), about, cbom }`);
  check('E2E-F.6', 'Summary shows the verdict, how many checks ran, and the action items first', rp.strip && rp.fix && /\d+ checks run/.test(rp.coverage), JSON.stringify({ strip: rp.strip, fix: rp.fix, coverage: rp.coverage }));
  check('E2E-F.7', 'every finding appears once in the action items; What was evaluated has a line per area; Configuration shows no finding card',
    rp.issues.length > 0 && new Set(rp.issues).size === rp.issues.length && rp.checks === 8 && rp.findingCards === 0, JSON.stringify(rp).slice(0, 240));
  check('E2E-F.8', 'area purpose lines are at most 15 words, and How we tested ends Configuration', rp.maxPurpose <= 15 && rp.about, JSON.stringify({ max: rp.maxPurpose, about: rp.about }));
  check('E2E-F.9', 'the header has Scan again, Download and More; the tabs are Summary, Configuration, Weaknesses, CBOM, History',
    ['Scan again', 'Download', 'More'].every((t) => rp.head.includes(t)) && !rp.head.includes('Delete') && rp.tabs.join() === 'Summary,Configuration,Weaknesses,CBOM,History', JSON.stringify({ head: rp.head, tabs: rp.tabs }));
  check('E2E-R.1', 'Configuration opens with a matrix of every TLS version; an accepted version opens to its suites (PRD-006 REQ-RV-3)',
    rp.matrix.rows >= 4 && rp.matrix.names[0] === 'TLS 1.3' && rp.matrix.opened && rp.matrix.suites > 0, JSON.stringify(rp.matrix));
  check('E2E-R.3', 'each version says what it is and whether that is right: an enabled old version "should be off", a disabled one "good"',
    Object.entries(rp.matrix.states).every(([v, t]) => (/^(SSL|TLS 1\.[01])/.test(v) ? /Enabled · should be off|Disabled · good/.test(t) : /Enabled|Disabled|Not determined/.test(t)))
    && /^Enabled: /.test(rp.matrix.summary), JSON.stringify({ states: rp.matrix.states, summary: rp.matrix.summary }));
  check('E2E-R.2', 'the CBOM tab shows the endpoint\'s components with downloads (PRD-006 REQ-RV-5)',
    rp.cbom.rows >= 3 && rp.cbom.counts >= 2 && rp.cbom.dl.includes('Download CycloneDX 1.7'), JSON.stringify(rp.cbom));
  const pdfs = await js(`const out = {};
    const scan = (await (await fetch('/api/v1/assets/${by[9443].id}')).json()).lastDone.id;
    for (const k of ['full', 'tls', 'cert']) {
      const r = await fetch('/api/v1/scans/' + scan + '/report.pdf?kind=' + k);
      const b = new Uint8Array(await r.arrayBuffer());
      out[k] = { status: r.status, magic: String.fromCharCode(...b.slice(0, 5)), size: b.length, name: r.headers.get('content-disposition') };
    }
    return out;`);
  check('E2E-P.1', 'the full, TLS and certificate reports download as real PDF files',
    ['full', 'tls', 'cert'].every((k) => pdfs[k].status === 200 && pdfs[k].magic === '%PDF-' && pdfs[k].size > 4000 && /\.pdf"$/.test(pdfs[k].name || '')), JSON.stringify(pdfs));
  const viaDialog = await js(`window.__printed = false; window.print = () => { window.__printed = true; };
    [...document.querySelectorAll('.page-head button')].find((b) => b.textContent.trim() === 'Download').click();
    await new Promise((r) => setTimeout(r, 300));
    const go = [...document.querySelectorAll('.modal button')].find((b) => b.textContent.trim() === 'Download');
    go.click();
    await new Promise((r) => setTimeout(r, 1500));
    return { printed: window.__printed, modalOpen: !!document.querySelector('.modal'), toast: document.querySelector('.toast')?.textContent || '' };`);
  check('E2E-P.2', 'Download → PDF saves a generated PDF; it never opens the print dialog', !viaDialog.printed && !viaDialog.modalOpen && /Downloaded/.test(viaDialog.toast), JSON.stringify(viaDialog));
  await go('#/inventory/sources');
  await sleep(1100);
  const src = await js(`return { heads: [...document.querySelectorAll('main section h2')].map((x) => x.textContent), rows: document.querySelectorAll('.source-list li').length,
    machines: document.querySelectorAll('.source-list a[href^="#/machines/"]').length }`);
  check('E2E-F.10', 'Inventory → Sources lists endpoint scans, machines and imported CBOMs, each opening its own page',
    ['Endpoint scans', 'Machine inventories', 'Imported CBOMs'].every((x) => src.heads.includes(x)) && src.rows >= 5 && src.machines >= 1, JSON.stringify(src));
  await shot('inventory-sources');
  await go('#/systems');
  await sleep(900);
  const sy = await js(`return { tabs: [...document.querySelectorAll('.tabs .tab')].map((t) => t.firstChild.textContent.trim()), menuCount: !!document.getElementById('nav-review-count') }`);
  check('E2E-F.11', 'Systems has Migration order and Decisions tabs, and the menu entry carries the decision count', sy.tabs.join('|') === 'Migration order|Decisions' && sy.menuCount, JSON.stringify(sy));

  // J9c (PRD-005 F-M6): every address the old menu used still lands on the page that replaced it.
  const anyId = by[9440].id;
  const moved = [['#/overview', '#/'], ['#/assets', '#/endpoints'], [`#/assets/${anyId}`, `#/endpoints/${anyId}`], [`#/reports/${anyId}`, `#/endpoints/${anyId}`],
    ['#/reports?tab=findings', '#/findings'], ['#/reports?tab=activity', '#/endpoints?tab=activity'], ['#/reports?tab=endpoints', '#/endpoints'],
    ['#/scans', '#/endpoints?tab=activity'], ['#/hosts', '#/machines'], ['#/imports', '#/inventory/sources'], ['#/inventory?tab=sources', '#/inventory/sources'],
    ['#/cbom', '#/inventory'], ['#/certificates', '#/inventory/certificates'], ['#/review', '#/systems?tab=decisions'], ['#/estate', '#/systems']];
  const wrong = [];
  for (const [from, to] of moved) {
    await go(from);
    await sleep(350);
    const at = await js(`return location.hash`);
    if (at !== to) wrong.push(`${from}→${at}`);
  }
  check('F-M6', 'every old address lands on the page that replaced it', wrong.length === 0, wrong.join(' '));
  // F-M4 and the inventory dashboard: figures first, lists one click deeper, downloads in the header.
  await go('#/inventory');
  await sleep(1200);
  const inv = await js(`return { dl: [...document.querySelectorAll('.download-menu button')].map((b) => b.textContent),
    tiles: document.querySelectorAll('.sumstrip .sumtile').length,
    cards: [...document.querySelectorAll('.dcard h2')].map((x) => x.textContent), ring: !!document.querySelector('.dcard svg.ring'),
    ranked: document.querySelectorAll('.rank-list .rank-row').length, bars: document.querySelectorAll('.dcard svg.hbar').length }`);
  check('F-M4', 'Inventory opens on a dashboard with Download (PDF report and CBOM) in the page header', inv.dl.includes('Download PDF') && inv.dl.includes('Download CBOM') && inv.tiles === 4, JSON.stringify(inv));
  check('E2E-D.1', 'the dashboard shows post-quantum status, what to replace first, protocols, certificates and sources, drawn as charts',
    ['Post-quantum status', 'Replace first', 'Protocol versions', 'Certificates', 'Sources'].every((c) => inv.cards.includes(c)) && inv.ring && inv.ranked > 0 && inv.bars >= 3, JSON.stringify(inv));
  const pdfInv = await js(`const r = await fetch('/api/v1/inventory/report.pdf', { headers: { 'X-Requested-With': 'cipherhorizon' } });
    const b = new Uint8Array(await r.arrayBuffer()); return { status: r.status, type: r.headers.get('content-type'), magic: String.fromCharCode(...b.slice(0, 5)), size: b.length }`);
  check('E2E-D.2', 'the inventory PDF report is a real PDF document', pdfInv.status === 200 && pdfInv.type === 'application/pdf' && pdfInv.magic === '%PDF-' && pdfInv.size > 4000, JSON.stringify(pdfInv));
  await go('#/inventory/algorithms');
  await sleep(900);
  const lst = await js(`return { sub: [...document.querySelectorAll('.subnav a')].map((a) => a.textContent).join('|'), current: document.querySelector('.subnav a[aria-current=page]')?.textContent,
    rows: document.querySelectorAll('main tbody tr').length, back: !!document.querySelector('main a[href="#/inventory"]') }`);
  check('E2E-D.3', 'each list is a page of its own, one click from the dashboard, with a way back', lst.sub === 'Algorithms|Keys|Certificates|Protocols|Software|Sources' && lst.current === 'Algorithms' && lst.rows > 0 && lst.back, JSON.stringify(lst));
  await go('#/inventory');
  await sleep(900);
  await shot('inventory');
  await go('#/nothing-here');
  await sleep(400);
  check('E2E-12.13', 'an unknown address gets a neutral explanation and a way back', /We could not find that page/.test(await js(`return document.querySelector('main').innerText`)));

  // J10: Help explains the levels and the score (UX-REVIEW-008 S4: no longer on About).
  await go('#/help');
  await sleep(800);
  const about = await js(`return document.querySelector('main').innerText`);
  check('E2E-04.3', 'Help explains the readiness levels, and that the TLS hygiene weights are the product\'s own choice and not a standard',
    /L3/.test(about) && /own choice/.test(about) && /not a standard/.test(about) && !/grade|SSL Labs/i.test(about));
  await shot('help');

  // J10b (PRD-005 REQ-NAV-3): About is reachable from the sidebar footer, the one link left there.
  await go('#/');
  await sleep(400);
  await js(`document.querySelector('.sidefoot a[href="#/about"]').click()`);
  await sleep(500);
  check('E2E-14.1', 'the sidebar footer leads to About', (await js(`return location.hash`)) === '#/about');
  // J10c: Help offers the inventory scripts: each can be read in place, its SHA-256 matches the text
  // served, and it downloads as plain text. No unsigned program is offered for download.
  await go('#/help');
  await sleep(600);
  const scripts = await js(`await new Promise((r) => setTimeout(r, 800));
    const rows = [...document.querySelectorAll('.dlbox .scriptrow')];
    const read = rows[1]?.querySelector('details.script-read');
    if (read) { read.open = true; read.dispatchEvent(new Event('toggle')); }
    await new Promise((r) => setTimeout(r, 800));
    const text = read?.querySelector('pre')?.textContent || '';
    const sha = rows[1]?.querySelector('.dlrow-sha')?.getAttribute('title') || '';
    const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))].map((b) => b.toString(16).padStart(2, '0')).join('');
    return { rows: rows.length, names: rows.map((r) => r.querySelector('code')?.textContent), shown: text.slice(0, 40), match: digest === sha,
      binaries: /collector\.exe|collector binary/i.test(document.querySelector('main').innerText) }`);
  check('E2E-14.2', 'Help offers the two inventory scripts, readable in place, with a SHA-256 that matches what is shown',
    scripts.rows === 2 && scripts.names.join() === 'cipherhorizon-inventory.ps1,cipherhorizon-inventory.sh' && /^#!\/bin\/sh/.test(scripts.shown) && scripts.match && !scripts.binaries, JSON.stringify(scripts));
  // A facts file, as the scripts write it, uploads through the same dialog and becomes a machine.
  await go('#/machines');
  await sleep(900);
  const facts = ['cipherhorizon-machine-facts\t1', 'script\tlinux-sh\t1.0.0', 'host\tname\tfacts-host-01', 'host\tos\tlinux', 'host\tprivilege\tadmin',
    'package-manager\tdpkg', 'package\tdpkg\topenssl\t3.5.1-1\tamd64', 'package\tdpkg\tlibgcrypt20\t1.11.0-7\tamd64'].join('\n') + '\n';
  await clickText('Upload results');
  await sleep(300);
  await js(`const dt = new DataTransfer(); dt.items.add(new File([${JSON.stringify(facts)}], 'cipherhorizon-facts-facts-host-01.txt', { type: 'text/plain' }));
    document.getElementById('cbom-file').files = dt.files; document.querySelector('.modal form').requestSubmit();`);
  await sleep(1500);
  const fh = await js(`return { hash: location.hash, text: document.querySelector('main').textContent }`);
  check('E2E-14.3', 'a facts file from the inventory script uploads and shows the machine with post-quantum verdicts',
    /#\/machines\/\d+/.test(fh.hash) && /facts-host-01/.test(fh.text) && /ML-KEM/.test(fh.text) && /quantum-vulnerable/.test(fh.text), fh.hash + ' ' + fh.text.slice(0, 120));
  await shot('facts-host');
  // REQ-INV-6: Inventory's "Add data" is the same dialog as the Scan page's link, collector how-to included.
  await go('#/inventory');
  await sleep(600);
  await clickText('Add data');
  await sleep(300);
  await clickText('Show me how', "document.querySelector('.modal')");
  await sleep(300);
  check('E2E-14.4', 'Inventory → Add data → Show me how opens the collector steps', (await js(`return document.querySelectorAll('.modal .steps .step').length`)) >= 3);
  await clickText('Close', "document.querySelector('.modal')");
  await sleep(300);

  // J11: dark mode and a phone-sized screen (AC-11.x, NFR accessibility).
  await viewport(1280, 900, true);
  await go('#/');
  await sleep(900);
  await shot('overview-dark');
  await go('#/inventory');
  await sleep(900);
  await shot('inventory-dark');
  await go(`#/endpoints/${by[9440].id}`);
  await sleep(700);
  await shot('report-dark');
  await viewport(390, 844, false, true);
  const over = {};
  for (const [name, at] of [['overview', '#/'], ['endpoints', '#/endpoints'], ['machines', '#/machines'], ['findings', '#/findings'], ['inventory', '#/inventory'], ['systems', '#/systems'], ['reports', '#/reports']]) {
    await go(at);
    await sleep(800);
    over[name] = await js(`return document.documentElement.scrollWidth - document.documentElement.clientWidth`);
    await shot(`${name}-mobile`);
  }
  check('NFR-a11y.1', 'no horizontal page scroll at 390 px wide on any place of the menu', Object.values(over).every((o) => o <= 1), JSON.stringify(over));
  await go('#/inventory');
  await sleep(800);
  const kp = await js(`const k = [...document.querySelectorAll('.sumstrip .sumtile')]; return { n: k.length, cols: new Set(k.map((e) => e.offsetLeft)).size }`);
  check('E2E-12.14', 'the inventory summary sits two per row on a phone', kp.n === 4 && kp.cols === 2, JSON.stringify(kp));
  await go(`#/endpoints/${by[9440].id}`);
  await sleep(700);
  const overflow2 = await js(`return document.documentElement.scrollWidth - document.documentElement.clientWidth`);
  check('NFR-a11y.2', 'no horizontal page scroll at 390 px wide (report page)', overflow2 <= 1, overflow2);
  await shot('report-mobile');
  await viewport(1280, 900);

  // The estate views (PRD-003 WP-8).
  await t1Phase({ check, js, go, sleep, shot, api, BASE, CONTROL, viewport });
  await estatePhase({ check, js, go, sleep, shot, api, BASE, send, viewport, clickText });
  await authPhase({ check, js, go, sleep, shot, api, viewport });
  await launchPhase({ check, js, go, sleep, shot, viewport, clickText });

  // Keyboard: Tab reaches the nav, Escape closes dialogs (NFR-a11y).
  await go('#/assets');
  await clickText('Add endpoints');
  await sleep(250);
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await sleep(250);
  check('NFR-a11y.3', 'Escape closes a dialog', (await js(`return document.querySelectorAll('.modal').length`)) === 0);
  const labels = await js(`return [...document.querySelectorAll('button, input, select, textarea')].filter(e => !e.closest('[hidden]') && !(e.textContent.trim() || e.getAttribute('aria-label') || e.labels?.length || e.getAttribute('title'))).length`);
  check('NFR-a11y.4', 'every control on the endpoints page has an accessible name', labels === 0, labels);

  // The browser logs every 4xx response as a console error. Two of them are our own deliberate negative
  // tests (an invalid target, a non-CBOM upload); anything else, and every exception, CSP violation or 5xx, is a failure.
  const expected = /status of 4\d\d/;
  const unexpected = consoleErrors.filter((e) => !expected.test(e));
  check('NFR-sec.csp', 'no script exceptions, CSP violations or server errors during the whole journey', unexpected.length === 0, unexpected.slice(0, 3).join(' | '));
  console.log(`      (${consoleErrors.length - unexpected.length} expected 4xx response(s) logged by the browser from the negative tests)`);
  if (process.env.SHOW4XX) for (const e of consoleErrors) console.log(`        ${e.slice(0, 160)}`);

  const failed = results.filter((r) => !r.ok);
  writeFileSync(join(OUT, 'results.json'), JSON.stringify({ base: BASE, browser: BROWSER, when: new Date().toISOString(), passed: results.length - failed.length, failed: failed.length, results }, null, 2));
  console.log(`\n${results.length - failed.length} passed, ${failed.length} failed; ${shotN} screenshots in ${OUT}`);
  return failed.length;
}

let code = 1;
try { code = await main(); } catch (e) { console.error('journey aborted:', e); }
try { ws?.close(); } catch { /* ignore */ }
proc.kill();
setTimeout(() => process.exit(code ? 1 : 0), 200);
