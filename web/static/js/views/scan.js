// Scan a URL: the product's main action (UX-DESIGN-005 principle 3). The same box sits on top of
// the Overview and opens from "Scan a URL" on the Endpoints page; either way a scan lands on the
// endpoint's report.
import { h } from '../dom.js';
import { api, ApiError } from '../api.js';
import { modal } from '../ui.js';

// normalise turns what a person types into the host:port the server stores, to find an
// endpoint that already exists (the server is the authority; this only finds the row).
function normalise(input) {
  let s = input.trim().replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '');
  if (!s) return '';
  if (s.startsWith('[')) return /\]:\d+$/.test(s) ? s.toLowerCase() : `${s.toLowerCase()}:443`;
  const parts = s.split(':');
  if (parts.length === 2) return s.toLowerCase();
  if (parts.length > 2) return `[${s.toLowerCase()}]:443`; // a bare IPv6 address
  return `${s.toLowerCase()}:443`;
}

/** quickScan finds or adds the endpoint, starts a scan and returns its id. */
export async function quickScan(target) {
  // An endpoint scanned before is scanned again, not added twice.
  const want = normalise(target);
  let asset = want ? (await api.assets('tls-endpoint').catch(() => [])).find((a) => a.address.toLowerCase() === want) : null;
  if (!asset) {
    try {
      asset = await api.addAsset(target);
    } catch (e) {
      if (!(e instanceof ApiError) || e.status !== 409) throw e;
      asset = (await api.assets()).find((a) => a.address.toLowerCase() === want);
      if (!asset) throw e;
    }
  }
  await api.scanAsset(asset.id);
  return asset.id;
}

/**
 * scanForm is the input and its button. A bad address is refused inline; a good one starts a scan
 * and opens the endpoint's report. id names the input (the Overview's is "scan-target").
 */
export function scanForm(id, onStarted) {
  const input = h('input', { type: 'text', id, class: 'scan-input', placeholder: 'example.com, https://example.com or host:port',
    autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Website or endpoint to scan', 'aria-describedby': `${id}-help` });
  const err = h('div', { class: 'scan-error', role: 'alert', hidden: true });
  const submit = h('button', { type: 'submit', class: 'btn btn-primary scan-button' }, 'Scan');
  const form = h('form', { class: 'scan-form', onsubmit: async (e) => {
    e.preventDefault();
    const target = input.value.trim();
    err.hidden = true;
    if (!target) { input.focus(); return; }
    submit.disabled = true;
    submit.textContent = 'Starting…';
    try {
      const assetId = await quickScan(target);
      if (onStarted) onStarted();
      location.hash = `#/endpoints/${assetId}`;
    } catch (ex) {
      err.textContent = ex.message;
      err.hidden = false;
      submit.disabled = false;
      submit.textContent = 'Scan';
      input.focus();
    }
  } }, input, submit);
  const help = h('p', { class: 'hint', id: `${id}-help` }, 'Only scan systems you own or are authorised to test. A scan makes a few hundred short TLS handshakes to that address and nothing else.');
  return { input, nodes: [form, err, help] };
}

/** openScanDialog is the "Scan a URL" button of the Endpoints page. */
export function openScanDialog() {
  modal('Scan a URL', (close) => {
    const { input, nodes } = scanForm('scan-dialog-target', close);
    const body = h('div', { class: 'modal-body scan-dialog' },
      h('p', { class: 'text-2' }, 'Enter a website or TLS endpoint. You get its protocols, cipher suites, certificate, weaknesses, post-quantum readiness and its CBOM.'),
      ...nodes);
    setTimeout(() => input.focus(), 0);
    return body;
  });
}
