// The guided parts of the interface: where to begin, how to collect from a machine,
// what to do next, and how complete an inventory is. Kept in one place so the same
// words are used wherever a person is told what to do.
import { h } from './dom.js';
import { button, copyButton, modal } from './ui.js';

export const LINUX_CMD = 'sudo ./cipherhorizon-collector run -o host.cbom.json';
export const WINDOWS_CMD = '.\\cipherhorizon-collector.exe run -o host.cbom.json';

/** A command in a monospace block with a copy control. */
export function commandBlock(cmd, label) {
  return h('div', { class: 'cmdblock' }, h('code', null, cmd), copyButton(cmd, label || 'command'));
}

function step(n, title, ...body) {
  return h('li', { class: 'step' }, h('span', { class: 'step-n', 'aria-hidden': 'true' }, String(n)),
    h('div', { class: 'step-body' }, h('h3', null, title), ...body));
}

/** The three steps for inventorying a machine, with the exact commands. */
export function collectSteps(onUpload) {
  const url = `${location.origin}/api/v1/hosts/ingest`;
  const curl = `curl -X POST "${url}" -H "X-Requested-With: cipherhorizon" -H "Content-Type: application/json" ` +
    '-H "Authorization: Bearer $CIPHERHORIZON_TOKEN" --data-binary @host.cbom.json';
  return h('ol', { class: 'steps' },
    step(1, 'Put the collector on the machine',
      h('p', null, 'Copy ', h('b', null, 'cipherhorizon-collector'), ' (about 4 MB) to the computer you want to inventory. It is a separate, small program: ',
        'it only reads files, starts no other program and makes no network connection.')),
    step(2, 'Run it',
      h('p', null, 'On Linux, as root:'), commandBlock(LINUX_CMD, 'Linux command'),
      h('p', null, 'On Windows, in an Administrator PowerShell:'), commandBlock(WINDOWS_CMD, 'Windows command'),
      h('p', { class: 'hint' }, 'Running with full rights lets it read more. Without them it still works, says so, and lists what it could not see.')),
    step(3, 'Upload the file here',
      h('p', null, 'Bring ', h('code', null, 'host.cbom.json'), ' back and upload it. Repeat whenever you want a fresh picture; each upload is kept so you can compare.'),
      onUpload ? button('Upload CBOM', onUpload, 'primary') : null,
      h('details', { class: 'more' }, h('summary', null, 'Automate the upload'),
        h('p', { class: 'hint' }, 'Any scheduler can send the file to this server. The two headers are required; the token is needed only if the server was started with one.'),
        commandBlock(curl, 'upload command'))));
}

/** A dialog with the collector how-to, for use from any page. */
export function collectDialog(onUpload) {
  modal('Inventory a machine', (close) => h('div', { class: 'modal-body' },
    collectSteps(onUpload ? () => { close(); onUpload(); } : null),
    h('div', { class: 'row end' }, button('Close', close))), { wide: true });
}

/** The first screen: two clear ways to begin. */
export function getStarted({ onAddEndpoints, onUpload }) {
  const card = (title, text, ...actions) => h('section', { class: 'card start-card' },
    h('h2', null, title), h('p', null, text), h('div', { class: 'row' }, actions));
  return h('div', { class: 'start' },
    h('div', { class: 'start-head' },
      h('h2', null, 'Welcome. Where would you like to begin?'),
      h('p', null, 'CipherHorizon shows where cryptography is used and how ready it is for the post-quantum era. There are two ways in, and you can do both.')),
    h('div', { class: 'grid two' },
      card('Check a server’s TLS',
        'Point it at a website or any service that speaks TLS (for example example.com:443). It tests the connection, rates how ready it is for post-quantum cryptography, and tells you what to fix first.',
        button('Add endpoints', onAddEndpoints, 'primary')),
      card('Inventory a machine',
        'Run a small program on a computer to list the cryptographic software installed on it, then upload the result here. It shows which algorithms a quantum computer could break.',
        button('Show me how', () => collectDialog(onUpload), 'primary'), button('Upload a CBOM', onUpload))),
    h('p', { class: 'hint start-foot' }, 'Everything stays on this machine. CipherHorizon makes no outside connections except the scans you start.'));
}

/** What to do next, chosen from the data. Returns { tone, text, action: { label, href|onClick } }. */
export function nextStep(f, hosts, priority, handlers) {
  const scanOrAdd = (label, fn) => ({ label, onClick: fn });
  if (f.assets && !f.scanned) {
    return { tone: 'info', text: 'Your endpoints have not been scanned yet. Scan them to see how ready each one is.', action: scanOrAdd('Scan all', handlers.scanAll) };
  }
  if (f.critical) {
    return { tone: 'bad', text: `${f.critical} critical finding${f.critical === 1 ? '' : 's'} need fixing first. They are the quickest way to reduce real risk.`, action: { label: 'Review findings', href: '#/findings' } };
  }
  if (f.hndlExposed) {
    return { tone: 'warn', text: `${f.hndlExposed} endpoint${f.hndlExposed === 1 ? ' is' : 's are'} exposed to harvest-now-decrypt-later. Turn on a hybrid post-quantum key exchange (X25519MLKEM768) so today’s traffic stays private.`, action: { label: 'See which', href: '#/assets' } };
  }
  if (f.certsExpiring) {
    return { tone: 'warn', text: `${f.certsExpiring} certificate${f.certsExpiring === 1 ? ' expires' : 's expire'} within 30 days. Renew ${f.certsExpiring === 1 ? 'it' : 'them'} before ${f.certsExpiring === 1 ? 'it' : 'they'} lapse${f.certsExpiring === 1 ? 's' : ''}.`, action: { label: 'See which', href: '#/assets' } };
  }
  if (!hosts.length) {
    return { tone: 'info', text: 'Endpoints look good. To see the cryptography inside your machines too, inventory one.', action: scanOrAdd('Show me how', handlers.collect) };
  }
  if (priority.length) {
    return { tone: 'info', text: 'Nothing urgent. The findings below are the best next improvements, worst first.', action: { label: 'All findings', href: '#/findings' } };
  }
  return { tone: 'good', text: 'Everything you monitor looks healthy. Set endpoints to rescan on a schedule so you hear about changes.', action: null };
}

// ---- inventory coverage -----------------------------------------------------------------------

/** "windows 10.0.26200" reads better as "Windows 10.0.26200". */
export const osLabel = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

const PRIVILEGE = { user: 'Standard user', admin: 'Administrator', root: 'root' };
export const privilegeLabel = (p) => PRIVILEGE[p] || (p ? p : 'Not recorded');

const SENSOR = { 'pe-files': 'Windows program files', 'windows-cng': 'Windows cryptography (CNG)', apt: 'Debian and Ubuntu packages' };
export const sensorLabel = (s) => SENSOR[s] || s;

/** How much of the machine the run could see: never "complete", because something is always unseen. */
export function accessState(cov) {
  if (!cov || !cov.privilege) return { label: 'Not recorded', tone: 'none', why: 'This CBOM does not say how much of the machine was read.' };
  const limited = cov.privilege === 'user' || (cov.sensors || []).some((s) => s.status === 'partial' || s.status === 'failed');
  return limited
    ? { label: 'Limited access', tone: 'warn', why: 'Some locations could not be read, so the inventory may be incomplete.' }
    : { label: 'Full access', tone: 'good', why: 'The collector ran with full rights and read everything in its scope.' };
}
