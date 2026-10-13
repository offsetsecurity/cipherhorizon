// The scan box: the product's main action (UX-DESIGN-005 principle 3), on top of the Overview. A
// scan lands on the report. The box says which protocol it will scan before it does (UX-DESIGN-007
// §5). On the TLS endpoints and SSH servers pages, the add dialog's Scan now does the same.
import { h } from '../dom.js';
import { api, ApiError } from '../api.js';
import { reportHref } from './assets.js';

// isSSH: the address names an SSH server by its scheme.
const isSSH = (s) => s.trim().toLowerCase().startsWith('ssh:');

/**
 * guessProtocol is what Automatic chooses, as the server does: the scheme first (ssh:// is SSH,
 * any other scheme TLS), then the port (22 is SSH). Empty input guesses nothing.
 */
export function guessProtocol(input) {
  const s = input.trim().toLowerCase();
  if (!s) return null;
  if (isSSH(s)) return 'ssh';
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(s)) return 'tls';
  const m = /^(?:\[[^\]]*\]|[^:/]+):(\d+)(?:\/|$)/.exec(s);
  return m && m[1] === '22' ? 'ssh' : 'tls';
}

// normalise turns what a person types into the host:port the server stores, to find an
// endpoint that already exists (the server is the authority; this only finds the row).
function normalise(input, protocol) {
  const port = protocol === 'ssh' ? 22 : 443; // an SSH server is on 22 unless said (PRD-008)
  let s = input.trim().replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '');
  if (!s) return '';
  if (s.startsWith('[')) return /\]:\d+$/.test(s) ? s.toLowerCase() : `${s.toLowerCase()}:${port}`;
  const parts = s.split(':');
  if (parts.length === 2) return s.toLowerCase();
  if (parts.length > 2) return `[${s.toLowerCase()}]:${port}`; // a bare IPv6 address
  return `${s.toLowerCase()}:${port}`;
}

/**
 * quickScan finds or adds the endpoint, starts a scan and returns it. protocol is the one the
 * person chose with the chip; when it is what Automatic would choose, the server decides.
 */
export async function quickScan(target, protocol = guessProtocol(target)) {
  // An endpoint scanned before is scanned again, not added twice.
  const want = normalise(target, protocol);
  const same = (a) => a.address.toLowerCase() === want && (a.protocol === 'ssh' ? 'ssh' : 'tls') === protocol;
  let asset = want ? (await api.assets().catch(() => [])).find(same) : null;
  if (!asset) {
    try {
      asset = protocol === guessProtocol(target) ? await api.addAsset(target)
        : await api.addAsset(target, '', [], 'auto', protocol);
    } catch (e) {
      if (!(e instanceof ApiError) || e.status !== 409) throw e;
      asset = (await api.assets()).find(same);
      if (!asset) throw e;
    }
  }
  await api.scanAsset(asset.id);
  return asset;
}

/**
 * scanForm is the input and its button. A bad address is refused inline; a good one starts a scan
 * and opens the endpoint's report. id names the input (the Overview's is "scan-target").
 */
export function scanForm(id, onStarted) {
  const input = h('input', { type: 'text', id, class: 'scan-input', placeholder: 'example.com, https://example.com or ssh://example.com',
    autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Website or endpoint to scan', 'aria-describedby': `${id}-help` });
  const err = h('div', { class: 'scan-error', role: 'alert', hidden: true });
  const submit = h('button', { type: 'submit', class: 'btn btn-primary scan-button' }, 'Scan');
  // The chip: what this box will scan, and a way to change it (UX-DESIGN-007 §5).
  let chosen = null; // null: follow what Automatic guesses
  const chip = h('button', { type: 'button', class: 'scan-chip', hidden: true });
  const protocolNow = () => chosen || guessProtocol(input.value);
  const drawChip = () => {
    const p = protocolNow();
    chip.hidden = !p;
    if (!p) return;
    const other = p === 'ssh' ? 'TLS' : 'SSH';
    chip.replaceChildren(h('span', null, `Scan as ${p.toUpperCase()}`), h('span', { class: 'scan-chip-change' }, 'change'));
    chip.setAttribute('aria-label', `Scan as ${p.toUpperCase()}; change to ${other}`);
  };
  chip.addEventListener('click', () => { chosen = protocolNow() === 'ssh' ? 'tls' : 'ssh'; drawChip(); input.focus(); });
  input.addEventListener('input', () => { if (!input.value.trim()) chosen = null; drawChip(); });
  const form = h('form', { class: 'scan-form', onsubmit: async (e) => {
    e.preventDefault();
    const target = input.value.trim();
    err.hidden = true;
    if (!target) { input.focus(); return; }
    submit.disabled = true;
    submit.textContent = 'Starting…';
    try {
      const asset = await quickScan(target, protocolNow());
      if (onStarted) onStarted();
      location.hash = reportHref(asset);
    } catch (ex) {
      err.textContent = ex.message;
      err.hidden = false;
      submit.disabled = false;
      submit.textContent = 'Scan';
      input.focus();
    }
  } }, input, chip, submit);
  const help = h('p', { class: 'hint', id: `${id}-help` }, 'Only scan systems you own or are authorised to test. A TLS scan makes a few hundred short handshakes; an SSH scan a handful of key exchanges, never a login.');
  return { input, nodes: [form, err, help] };
}
