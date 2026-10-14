// Screenshots for the README and the docs site (PRD-007 REQ-LM-3), taken from demo data only, so
// no real endpoint ever appears in published images.
//
//   go run ./cmd/demo-targets &
//   cipherhorizon serve --no-login --allow-loopback --db shots.db --addr 127.0.0.1:8092 &
//   node testing/e2e/screenshots.mjs --base http://127.0.0.1:8092 --out docs/img
//
// It adds the demo targets, scans them, waits, and saves PNGs of the main pages in light and dark.
// BROWSER may name Chrome or Edge; the default is Edge on Windows, else google-chrome.
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const arg = (name, def) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : def; };
const BASE = arg('base', 'http://127.0.0.1:8092');
const OUT = arg('out', 'docs/img');
const DEMO = Number(arg('demo-port', '9440'));
const BROWSER = process.env.BROWSER || (process.platform === 'win32'
  ? 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe' : 'google-chrome');
mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const api = async (method, path, body) => {
  const r = await fetch(BASE + path, { method, headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'cipherhorizon' }, body: body ? JSON.stringify(body) : undefined });
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${await r.text()}`);
  return r.status === 204 ? null : r.json();
};

// 1. Demo data: the targets with a known posture, scanned once. TLS endpoints, and SSH servers from
// base+20 (hybrid, classical, legacy, ML-DSA host key, hardened to meet the baseline).
const targets = [...[0, 1, 2, 3].map((o) => `127.0.0.1:${DEMO + o}`), `smtp://127.0.0.1:${DEMO + 11}`,
  ...[20, 21, 22, 23, 27].map((o) => `ssh://127.0.0.1:${DEMO + o}`)];
await api('POST', '/api/v1/assets/bulk', { text: targets.join('\n'), tags: ['demo'] });
await api('POST', '/api/v1/scans', { all: true });
for (let i = 0; i < 240; i++) {
  const running = await api('GET', '/api/v1/scans?status=running');
  const queued = await api('GET', '/api/v1/scans?status=queued');
  if (!running.length && !queued.length) break;
  await sleep(1000);
}
const assets = await api('GET', '/api/v1/assets?kind=endpoint');
const byPort = Object.fromEntries(assets.map((a) => [a.port, a]));

// 2. The browser.
const port = 9600 + Math.floor(Math.random() * 300);
const proc = spawn(BROWSER, ['--headless=new', '--disable-gpu', '--hide-scrollbars', `--remote-debugging-port=${port}`,
  `--user-data-dir=${mkdtempSync(join(tmpdir(), 'shots-'))}`, '--no-first-run', 'about:blank'], { stdio: 'ignore' });
let ws, opened, seq = 0;
const pending = new Map();
for (let i = 0; i < 100 && !ws; i++) {
  try {
    const page = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find((t) => t.type === 'page');
    if (page) { ws = new WebSocket(page.webSocketDebuggerUrl); opened = new Promise((r) => { ws.onopen = r; }); }
  } catch { /* starting */ }
  if (!ws) await sleep(150);
}
await opened;
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && pending.has(d.id)) { pending.get(d.id)(d.result); pending.delete(d.id); } };
const send = (method, params = {}) => new Promise((res) => { const id = ++seq; pending.set(id, res); ws.send(JSON.stringify({ id, method, params })); });
await send('Page.enable');

const shots = [
  ['overview', '#/'],
  ['report-hybrid', `#/endpoints/${byPort[DEMO].id}`],
  ['report-legacy', `#/endpoints/${byPort[DEMO + 3].id}`],
  ['report-starttls', `#/endpoints/${byPort[DEMO + 11].id}`],
  ['endpoints', '#/endpoints'],
  ['ssh-servers', '#/ssh'],
  ['report-ssh', `#/ssh/${byPort[DEMO + 20].id}`],
  ['report-ssh-baseline', `#/ssh/${byPort[DEMO + 20].id}?tab=configuration`],
  ['inventory', '#/inventory'],
];
for (const dark of [false, true]) {
  await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: dark ? 'dark' : 'light' }] });
  for (const [name, hash] of shots) {
    if (dark && !['overview', 'report-hybrid'].includes(name)) continue;
    await send('Page.navigate', { url: `${BASE}/${hash}` });
    await sleep(1800);
    const shot = await send('Page.captureScreenshot', { format: 'png' });
    const file = join(OUT, `${name}${dark ? '-dark' : ''}.png`);
    writeFileSync(file, Buffer.from(shot.data, 'base64'));
    console.log('wrote', file);
  }
}
proc.kill();
process.exit(0);
