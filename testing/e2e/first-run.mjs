// Success measure M7 (PRD-003): a new user, with the guided first run, reaches "systems ranked with
// reasons" in at most 5 clicks and 10 minutes. Run against a FRESH server and the demo targets:
//
//   cipherhorizon serve --allow-loopback --db first.db --addr 127.0.0.1:8092
//   demo-targets
//   node testing/e2e/first-run.mjs [--base http://127.0.0.1:8092]
//
// It counts every click the flow needs, and fails if there are more than five or it takes over 10 minutes.
import { spawn } from 'node:child_process';
import { mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const arg = (name, def) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : def; };
const BASE = arg('base', 'http://127.0.0.1:8092');
const TARGET = arg('target', '127.0.0.1:9441');
const BROWSER = arg('browser', [
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Google/Chrome/Application/chrome.exe', '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/microsoft-edge'].find(existsSync));
if (!BROWSER) { console.error('no Chromium-based browser found; pass --browser PATH'); process.exit(2); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const port = 9333 + Math.floor(Math.random() * 500);
const proc = spawn(BROWSER, ['--headless=new', '--disable-gpu', `--remote-debugging-port=${port}`, `--user-data-dir=${mkdtempSync(join(tmpdir(), 'first-run-'))}`,
  '--no-first-run', '--window-size=1280,900', ...(process.env.CI ? ['--no-sandbox'] : []), 'about:blank'], { stdio: 'ignore' });
let ws, seq = 0;
const pending = new Map();
for (let i = 0; i < 100 && !ws; i++) {
  try { const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json(); const p = list.find((t) => t.type === 'page'); if (p) { ws = new WebSocket(p.webSocketDebuggerUrl); break; } } catch { /* starting */ }
  await sleep(150);
}
await new Promise((res, rej) => { if (ws.readyState === 1) res(); ws.onopen = res; ws.onerror = rej; });
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && pending.has(d.id)) { const { res, rej } = pending.get(d.id); pending.delete(d.id); d.error ? rej(new Error(d.error.message)) : res(d.result); } };
const send = (method, params = {}) => new Promise((res, rej) => { const id = ++seq; pending.set(id, { res, rej }); ws.send(JSON.stringify({ id, method, params })); });
const js = async (expr) => { const r = await send('Runtime.evaluate', { expression: `(async () => { ${expr} })()`, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw new Error(r.exceptionDetails.text); return r.result.value; };

let clicks = 0;
const click = async (what, expr) => { const ok = await js(expr); if (!ok) throw new Error(`could not click: ${what}`); clicks++; console.log(`click ${clicks}: ${what}`); await sleep(400); };
const started = Date.now();
let ok = false;
try {
  await send('Page.enable');
  await send('Page.navigate', { url: `${BASE}/#/` });
  await sleep(1200);
  await click('Add endpoints (first-run door)', `const b = [...document.querySelectorAll('.start button')].find((x) => x.textContent.trim() === 'Add endpoints'); b?.click(); return !!b`);
  await js(`document.getElementById('add-target').value = ${JSON.stringify(TARGET)}`);
  await click('Add endpoint (submit)', `const f = document.querySelector('.modal form'); f.requestSubmit(); return !!f`);
  // The estate scans what was added and refreshes itself; wait for a ranked row.
  const deadline = Date.now() + 120000;
  let row = false;
  while (Date.now() < deadline && !row) { await sleep(1000); row = await js(`return document.querySelectorAll('main tbody tr:not(.why-row)').length > 0 && !document.querySelector('.start')`); }
  if (!row) throw new Error('no ranked system appeared');
  // Wait for the scan to finish so the reasons say what was observed.
  let observed = false;
  while (Date.now() < deadline && !observed) { await sleep(1500); observed = await js(`return /observed/.test(document.querySelector('main tbody')?.innerText || '')`); }
  // Let the refresh loop settle: it stops by itself once no scan is queued or running.
  while (Date.now() < deadline && (await (await fetch(`${BASE}/api/v1/scans?status=running`)).json()).length + (await (await fetch(`${BASE}/api/v1/scans?status=queued`)).json()).length) await sleep(1000);
  await sleep(4000);
  await click('Why (open the reasons)', `const b = document.querySelector('main tbody tr button'); b?.click(); return !!b`);
  const reasons = await js(`return document.querySelectorAll('.why-row:not([hidden]) .why-rule').length`);
  const seconds = Math.round((Date.now() - started) / 1000);
  ok = observed && reasons === 4 && clicks <= 5 && seconds <= 600;
  console.log(`${ok ? 'PASS' : 'FAIL'}  M7: ${clicks} clicks, ${seconds} s, ${reasons} rules shown, observed=${observed}`);
} catch (e) { console.error('FAIL  M7:', e.message); }
try { ws.close(); } catch { /* ignore */ }
proc.kill();
setTimeout(() => process.exit(ok ? 0 : 1), 200);
