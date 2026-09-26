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
const location_is_list = (h) => h === '#/assets';
const clickText = (text, scope = 'document') => js(`
  const b = [...${scope}.querySelectorAll('button, a')].find(x => x.textContent.trim() === ${JSON.stringify(text)});
  if (!b) return false; b.click(); return true;`);

// ---- the journey --------------------------------------------------------------------------------------

async function main() {
  await connect();
  await send('Page.enable'); await send('Runtime.enable'); await send('Log.enable');
  await viewport(1280, 900);

  // J1: first run shows an empty state that leads to adding endpoints (US-01).
  await go('#/');
  const empty = await js(`return document.querySelector('.start')?.innerText || ''`);
  check('E2E-01.0', 'first run: dashboard offers to add endpoints', /Add endpoints/.test(empty), empty.slice(0, 80));
  const startText = await js(`return document.querySelector('main').innerText`);
  check('E2E-12.1', 'first run shows two clear ways to begin: check a server, inventory a machine',
    /Check a server/.test(startText) && /Inventory a machine/.test(startText) && /Show me how/.test(startText), startText.slice(0, 120));
  await clickText('Show me how');
  await sleep(300);
  const howto = await js(`const m = document.querySelector('.modal'); return { text: m ? m.innerText : '', cmds: m ? m.querySelectorAll('.cmdblock').length : 0, copies: m ? m.querySelectorAll('.cmdblock .copybtn').length : 0 }`);
  check('E2E-12.2', 'the how-to dialog gives copyable Linux and Windows collector commands', howto.cmds >= 2 && howto.copies === howto.cmds && /cipherhorizon-collector/.test(howto.text) && /Administrator PowerShell/.test(howto.text), JSON.stringify(howto).slice(0, 120));
  await shot('how-to-collect-dialog', { full: false });
  await clickText('Close', "document.querySelector('.modal')");
  await sleep(300);
  await shot('dashboard-empty');

  // J2: add a single endpoint (AC-01.1) with a name and tags; a bad one shows a clear error (AC-01.3).
  await clickText('Add endpoints');
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
  check('E2E-01.1', 'a single endpoint can be added with name and tags', assets.length === 1 && assets[0].name === 'modern-hybrid' && assets[0].tags.join() === 'demo,web', JSON.stringify(assets.map((a) => a.name)));

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
  check('E2E-11.4', 'the metadata address was not added', !assets.some((a) => a.host === '169.254.169.254') && assets.length === 7, assets.length);

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
  check('E2E-04.1', 'L0/L1 endpoints are flagged exposed to harvest-now-decrypt-later', by[9441]?.lastDone?.hndlExposed && by[9442]?.lastDone?.hndlExposed && !by[9440]?.lastDone?.hndlExposed);

  await go('#/assets');
  await sleep(600);
  await shot('endpoints-results');
  await go('#/');
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
  await clickText('TLS details');
  await sleep(300);
  await shot('asset-terrible-legacy-tls-details');
  await clickText(`Findings (${(await api(`/api/v1/scans/${by[9443].lastDone.id}/evaluation`)).findings.length})`);
  await sleep(300);
  const fnd = await js(`return { cards: document.querySelectorAll('.finding').length, cites: document.querySelectorAll('.finding .cites a').length }`);
  check('E2E-05.2', 'findings are listed with citations', fnd.cards > 0 && fnd.cites >= fnd.cards, JSON.stringify(fnd));
  await shot('asset-terrible-legacy-findings');
  await go(`#/assets/${by[9440].id}`);
  await sleep(500);
  await clickText('TLS details');
  await sleep(300);
  await shot('asset-modern-hybrid-tls-details');

  // J6: history and change over time (US-07): flip the toggle target to hybrid and rescan.
  const t = by[9445];
  check('E2E-07.pre', 'the toggle target starts classical (L1)', t.lastDone.readinessLevel === 1, t.lastDone.readinessLevel);
  const flip = await fetch(`${CONTROL}/pq/on`, { method: 'POST' });
  check('E2E-07.setup', 'operator enables hybrid key exchange on the target', flip.ok, flip.status);
  await go(`#/assets/${t.id}`);
  await sleep(600);
  await clickText('Scan now');
  const after = await waitFor(async () => { const a = await api(`/api/v1/assets/${t.id}`); return a.latest?.status === 'done' && a.lastDone.id !== t.lastDone.id ? a : null; }, 60000);
  check('E2E-07.1', 'a rescan runs and records a second result', !!after && after.lastDone.readinessLevel === 3, after?.lastDone?.readinessLevel);
  await go(`#/assets/${t.id}?tab=history`);
  await sleep(500);
  await clickText('History (2)');
  await sleep(900);
  const hist = await js(`return { dots: document.querySelectorAll('svg.chart circle.dot').length, diff: document.body.innerText.match(/\\d+ change\\(s\\)[^\\n]*/)?.[0] || '', better: [...document.querySelectorAll('.impact')].map(x => x.textContent).join() }`);
  check('E2E-07.3', 'history chart shows both scans and the diff shows the improvement', hist.dots === 2 && /better/.test(hist.diff) && /better/.test(hist.better), JSON.stringify(hist));
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
  await clickText('Edit');
  await sleep(250);
  await js(`document.getElementById('e-name').value = 'renamed in the UI'; document.getElementById('e-notes').value = 'edited by the journey'; document.querySelector('.modal form').requestSubmit();`);
  await sleep(700);
  const edited = await api(`/api/v1/assets/${hostile.id}`);
  check('E2E-01.5a', 'name and notes can be edited from the endpoint page', edited.name === 'renamed in the UI' && edited.notes === 'edited by the journey', edited.name);
  await clickText('Delete');
  await sleep(250);
  await shot('delete-confirmation', { full: false });
  await clickText('Cancel', "document.querySelector('.modal')");
  await sleep(250);
  check('E2E-01.5b', 'canceling the confirmation keeps the endpoint', (await fetch(`${BASE}/api/v1/assets/${hostile.id}`)).status === 200);
  await clickText('Delete');
  await sleep(250);
  await clickText('Delete', "document.querySelector('.modal')");
  await sleep(800);
  check('E2E-01.5c', 'confirming deletes the endpoint and returns to the list', (await fetch(`${BASE}/api/v1/assets/${hostile.id}`)).status === 404 && location_is_list(await js(`return location.hash`)));

  // J9: hosts (US-09): upload a CBOM through the file input.
  await go('#/hosts');
  await sleep(500);
  await shot('hosts-empty');
  const hostsEmpty = await js(`return document.querySelector('main').innerText`);
  check('E2E-12.3', 'the empty Hosts page teaches the three steps with the exact command', /Inventory your first machine/.test(hostsEmpty) && /run -o host\.cbom\.json/.test(hostsEmpty) && /Automate the upload/.test(hostsEmpty), hostsEmpty.slice(0, 100));
  const bom = { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, metadata: { timestamp: '2026-09-21T10:00:00Z', component: { 'bom-ref': 'host:web-01', type: 'device', name: 'web-01' } },
    components: [
      { 'bom-ref': 'crypto/rsa', type: 'cryptographic-asset', name: 'RSA', cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'pke' }, oid: '1.2.840.113549.1.1.1' } },
      { 'bom-ref': 'crypto/sha256', type: 'cryptographic-asset', name: 'SHA-256', cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'hash' }, oid: '2.16.840.1.101.3.4.2.1' } },
      { 'bom-ref': 'pkg/libgcrypt20', type: 'library', name: 'libgcrypt20', version: '1.10.3' }],
    dependencies: [{ ref: 'pkg/libgcrypt20', provides: ['crypto/rsa', 'crypto/sha256'] }] };
  await clickText('Upload CBOM');
  await sleep(250);
  await shot('host-upload-dialog', { full: false });
  await js(`const dt = new DataTransfer(); dt.items.add(new File([${JSON.stringify(JSON.stringify(bom))}], 'web-01.cbom.json', { type: 'application/json' }));
    document.getElementById('cbom-file').files = dt.files; document.querySelector('.modal form').requestSubmit();`);
  await sleep(1000);
  const host = await js(`return { hash: location.hash, text: document.querySelector('main').innerText }`);
  check('E2E-10.1', 'a CBOM uploads and opens the host page with verdicts', /#\/hosts\/\d+/.test(host.hash) && /quantum-vulnerable/.test(host.text) && /quantum-safe/.test(host.text), host.hash);
  check('E2E-10.2', 'the host page states capability is not use', /Capability, not use/.test(host.text));
  check('E2E-10.3', 'the package is shown as providing the algorithms', /libgcrypt20/.test(host.text));
  check('E2E-12.4', 'a CBOM that records no coverage is shown as Not recorded, never as complete', /Inventory coverage/.test(host.text) && /Not recorded/.test(host.text) && !/Full access/.test(host.text), host.text.slice(0, 80));
  await shot('host-detail');
  const badUpload = await fetch(`${BASE}/api/v1/hosts/ingest`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'cipherhorizon' }, body: '{"hello":"world"}' });
  check('E2E-10.4', 'a non-CBOM upload is refused with 400', badUpload.status === 400, badUpload.status);
  await go('#/hosts');
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
  await go('#/hosts');
  await sleep(600);
  const hostsList = await js(`return document.querySelector('main').innerText`);
  check('E2E-12.8', 'the Hosts list shows system and access for each machine', /Limited access/.test(hostsList) && /Not recorded/.test(hostsList) && /Windows 10\.0\.26200/.test(hostsList), hostsList.slice(0, 120));
  await clickText('How do I collect?');
  await sleep(300);
  check('E2E-12.9', 'the collector how-to is reachable from a populated Hosts page', (await js(`return document.querySelectorAll('.modal .cmdblock').length`)) >= 2);
  await clickText('Close', "document.querySelector('.modal')");
  await sleep(300);

  // J9c: the dashboard advises, lays out six cards as 3 x 2, and the old and new addresses both work.
  await go('#/');
  await sleep(900);
  const dash = await js(`const k = [...document.querySelectorAll('.grid.kpis.six .kpi')]; return { banner: document.querySelector('.nextstep')?.innerText || '', cards: k.length, rows: new Set(k.map((e) => e.offsetTop)).size, cols: new Set(k.map((e) => e.offsetLeft)).size, hndl: document.querySelector('main').innerText.includes('Recorded today, readable later') }`);
  check('E2E-12.10', 'the dashboard states a next step', /next step/i.test(dash.banner) && dash.banner.length > 30, dash.banner);
  check('E2E-12.11', 'six KPI cards sit three by two, and the jargon card explains itself', dash.cards === 6 && dash.rows === 2 && dash.cols === 3 && dash.hndl, JSON.stringify(dash));
  await go('#/endpoints');
  await sleep(600);
  check('E2E-12.12', '#/endpoints is an alias of the endpoints page', (await js(`return document.querySelector('h1')?.innerText`)) === 'Endpoints');
  await go('#/nothing-here');
  await sleep(400);
  check('E2E-12.13', 'an unknown address gets a neutral explanation and a way back', /We could not find that page/.test(await js(`return document.querySelector('main').innerText`)));

  // J10: about page (readiness legend and methodology).
  await go('#/about');
  await sleep(500);
  const about = await js(`return document.querySelector('main').innerText`);
  check('E2E-04.3', 'About explains the readiness levels, and that the TLS hygiene weights are the product\'s own choice and not a standard',
    /L3/.test(about) && /own choice/.test(about) && /not a standard/.test(about) && !/grade|SSL Labs/i.test(about));
  await shot('about');

  // J11: dark mode and a phone-sized screen (AC-11.x, NFR accessibility).
  await viewport(1280, 900, true);
  await go('#/');
  await sleep(900);
  await shot('dashboard-dark');
  await go(`#/assets/${by[9440].id}`);
  await sleep(700);
  await shot('asset-overview-dark');
  await viewport(390, 844, false, true);
  await go('#/');
  await sleep(900);
  const overflow = await js(`return document.documentElement.scrollWidth - document.documentElement.clientWidth`);
  check('NFR-a11y.1', 'no horizontal page scroll at 390 px wide (dashboard)', overflow <= 1, overflow);
  const kp = await js(`const k = [...document.querySelectorAll('.grid.kpis .kpi')]; return { n: k.length, cols: new Set(k.map((e) => e.offsetLeft)).size }`);
  check('E2E-12.14', 'KPI cards sit two per row on a phone', kp.n === 6 && kp.cols === 2, JSON.stringify(kp));
  await shot('dashboard-mobile');
  await go(`#/assets/${by[9440].id}`);
  await sleep(700);
  const overflow2 = await js(`return document.documentElement.scrollWidth - document.documentElement.clientWidth`);
  check('NFR-a11y.2', 'no horizontal page scroll at 390 px wide (endpoint page)', overflow2 <= 1, overflow2);
  await shot('asset-overview-mobile');
  await go('#/assets');
  await sleep(700);
  await shot('endpoints-mobile');
  await viewport(1280, 900);

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
