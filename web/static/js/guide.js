// The guided parts of the interface: where to begin, how to collect from a machine,
// what to do next, and how complete an inventory is. Kept in one place so the same
// words are used wherever a person is told what to do.
import { h, svg, clear, fmtBytes } from './dom.js';
import { button, copyButton, modal, toast } from './ui.js';
import { api } from './api.js';

export const LINUX_CMD = 'sudo sh ./cipherhorizon-inventory.sh';
// Windows: unblock the downloaded file, then run it under RemoteSigned, which still refuses
// unsigned scripts that come from the internet. Bypass is offered only as the fallback (audit L-16).
export const WINDOWS_CMD = 'Unblock-File .\\cipherhorizon-inventory.ps1; powershell -NoProfile -ExecutionPolicy RemoteSigned -File .\\cipherhorizon-inventory.ps1';
export const WINDOWS_CMD_FALLBACK = 'powershell -NoProfile -ExecutionPolicy Bypass -File .\\cipherhorizon-inventory.ps1';
export const VERIFY_WINDOWS = 'Get-FileHash .\\cipherhorizon-inventory.ps1';
export const VERIFY_LINUX = 'sha256sum cipherhorizon-inventory.sh';
export const VERIFY_OFFLINE = 'cipherhorizon scripts list';

/** A command in a monospace block with a copy control. */
export function commandBlock(cmd, label) {
  return h('div', { class: 'cmdblock' }, h('code', null, cmd), copyButton(cmd, label || 'command'));
}

function step(n, title, ...body) {
  return h('li', { class: 'step' }, h('span', { class: 'step-n', 'aria-hidden': 'true' }, String(n)),
    h('div', { class: 'step-body' }, h('h3', null, title), ...body));
}

/** One inventory script: its platform, a download, its SHA-256, and its text to read in place.
 * The scripts are plain text served by this server, so nobody has to trust an unsigned program:
 * what they read is what runs. A download needs the server's access token, so it is a button
 * that fetches and saves the file (api.download), not a link. */
function scriptRow(s) {
  const source = h('pre', { class: 'script-source' }, 'Loading…');
  const read = h('details', { class: 'more script-read' }, h('summary', null, 'Read the script'), source);
  read.addEventListener('toggle', () => {
    if (!read.open || source.dataset.loaded) return;
    api.inventoryScript(s.name).then((text) => { source.textContent = text; source.dataset.loaded = '1'; })
      .catch((e) => { source.textContent = e.message; });
  });
  return h('div', { class: 'dlrow scriptrow' },
    h('div', { class: 'dlrow-main' },
      h('span', { class: 'dlrow-os' }, s.platform),
      h('code', { class: 'muted' }, s.name),
      h('span', { class: 'dlrow-size muted' }, `${fmtBytes(s.size)} · ${s.signatures} signatures`)),
    h('div', { class: 'dlrow-actions' },
      h('span', { class: 'dlrow-sha mono muted', title: s.sha256 }, `sha256:${s.sha256.slice(0, 12)}…`, copyButton(s.sha256, 'the SHA-256 checksum')),
      button('Download', () => api.download(`/api/v1/collector/scripts/${encodeURIComponent(s.name)}?download=1`, s.name)
        .then(() => toast(`Downloaded ${s.name}`, 'success')).catch((e) => toast(e.message, 'error')), 'secondary', { class: 'btn btn-sm btn-secondary' })),
    read);
}

/** Where a signature looks, in one line, from its parameters. */
function whereOf(sig) {
  const p = sig.params || {};
  const list = (v) => (v || '').split('|').join(', ');
  switch (sig.capability) {
    case 'registry': return `${p.key}${p.depth && p.depth !== '0' ? ` (and ${p.depth} levels below)` : ''}: ${list(p.values)}`;
    case 'certstore': return `${list(p.locations)} stores: ${list(p.stores)}`;
    case 'file': return `${list(p.names)} under ${list(p.roots)}`;
    case 'program': return `installed programs matching ${p.match}`;
    case 'lines': return `${list(p.paths)}, lines matching ${p.match}`;
    case 'package': return `packages matching ${p.match}`;
    case 'certfiles': return list(p.dirs);
    default: return '';
  }
}

/** Everything the scripts collect, from the signature database (PRD-006 REQ-SG-4). */
export function signaturesList() {
  const box = h('details', { class: 'more signatures-list' }, h('summary', null, 'What the scripts collect, item by item'));
  let loaded = false;
  box.addEventListener('toggle', () => {
    if (!box.open || loaded) return;
    loaded = true;
    api.inventorySignatures().then((db) => {
      const per = (platform) => db.signatures.filter((x) => x.platform === platform);
      box.append(
        h('p', { class: 'hint' }, `Signature database ${db.version}. ${db.about}`),
        ...['windows', 'linux'].map((pl) => h('div', null,
          h('h4', null, pl === 'windows' ? `Windows (${per(pl).length})` : `Linux (${per(pl).length})`),
          h('div', { class: 'tablewrap' }, h('table', { class: 'compact sigtable' },
            h('thead', null, h('tr', null, ['What', 'From where', 'How', 'Why'].map((c) => h('th', { scope: 'col' }, c)))),
            h('tbody', null, per(pl).map((x) => h('tr', null,
              h('td', null, h('b', null, x.title), h('div', { class: 'hint mono' }, x.id)),
              h('td', null, h('code', null, whereOf(x))),
              h('td', { class: 'muted' }, x.how),
              h('td', { class: 'muted' }, x.why)))))))));
    }).catch((e) => { box.appendChild(h('p', { class: 'hint' }, e.message)); });
  });
  return box;
}

/** The inventory scripts this server hands out, fetched once and patched in (a modal's body
 * is built synchronously, so the box starts as a placeholder). */
export function inventoryScriptsBlock() {
  const box = h('div', { class: 'dlbox' }, h('p', { class: 'hint' }, 'Loading the inventory scripts…'));
  api.inventoryScripts().then(({ scripts }) => {
    clear(box);
    for (const s of scripts) box.appendChild(scriptRow(s));
    box.appendChild(signaturesList());
  }).catch(() => { clear(box); box.appendChild(h('p', { class: 'hint' }, 'Could not load the inventory scripts from this server.')); });
  return box;
}

/** The three steps for inventorying a machine, with the exact commands. */
export function collectSteps(onUpload) {
  const url = `${location.origin}/api/v1/hosts/ingest`;
  const curl = `curl -X POST "${url}" -H "X-Requested-With: cipherhorizon" -H "Content-Type: text/plain" ` +
    '-H "Authorization: Bearer $CIPHERHORIZON_TOKEN" --data-binary @cipherhorizon-facts-$(hostname).txt';
  return h('ol', { class: 'steps' },
    step(1, 'Get the script for the machine',
      h('p', null, 'A short script in plain text: PowerShell for Windows (5.1 or later), shell for Linux (Debian, Ubuntu, RHEL, Fedora, SUSE, Alpine). Each is a small engine with a few read-only capabilities; what it collects comes from this server’s signature database, written into the script and listed below. It installs nothing, changes nothing, runs no other program and makes no network connection.'),
      inventoryScriptsBlock(),
      h('details', { class: 'more verify-scripts' }, h('summary', null, 'Check the script before you run it'),
        h('p', { class: 'hint' }, 'The SHA-256 of the file you downloaded must match the one shown above:'),
        commandBlock(VERIFY_WINDOWS, 'Windows check'), commandBlock(VERIFY_LINUX, 'Linux check'),
        h('p', { class: 'hint' }, 'To check without trusting this server, ask the CipherHorizon program of the same version, or the inventory-scripts.sha256 file signed with each release; both list the same hashes:'),
        commandBlock(VERIFY_OFFLINE, 'offline check'))),
    step(2, 'Run it on the machine',
      h('p', null, 'On Windows, in PowerShell (as Administrator for the fullest picture):'), commandBlock(WINDOWS_CMD, 'Windows command'),
      h('details', { class: 'more' }, h('summary', null, 'If a policy refuses it'),
        h('p', { class: 'hint' }, 'Some machines refuse every unsigned script. Read the script first, then run it with the policy set aside for this one process only:'),
        commandBlock(WINDOWS_CMD_FALLBACK, 'fallback Windows command')),
      h('p', null, 'On Linux (as root for the fullest picture):'), commandBlock(LINUX_CMD, 'Linux command'),
      h('p', { class: 'hint' }, 'It writes ', h('code', null, 'cipherhorizon-facts-<machine>.txt'),
        ': the machine’s name and operating system, its cryptographic packages and its public certificates. Plain text, one fact per line: open it and check what will leave the machine. Private keys are never read.')),
    step(3, 'Upload the file here',
      h('p', null, 'This server turns the facts into a CycloneDX CBOM with a post-quantum verdict for every algorithm. Upload again whenever you want a fresh picture; each upload is kept so you can compare.'),
      onUpload ? button('Upload the file', onUpload, 'primary') : null,
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

// Each door on a first-run screen carries its own icon and tone, so the choice is a shape and a
// colour to recognise at a glance, not just a heading among identical white cards.
const DOOR_ICONS = {
  scan: svg('svg', { viewBox: '0 0 20 20', fill: 'none', 'aria-hidden': 'true' },
    svg('circle', { cx: '8.5', cy: '8.5', r: '5.7', stroke: 'currentColor', 'stroke-width': '1.7' }),
    svg('path', { d: 'M12.7 12.7 17 17', stroke: 'currentColor', 'stroke-width': '1.7', 'stroke-linecap': 'round' })),
  inventory: svg('svg', { viewBox: '0 0 20 20', fill: 'none', 'aria-hidden': 'true' },
    svg('rect', { x: '3', y: '3.5', width: '14', height: '5', rx: '1.2', stroke: 'currentColor', 'stroke-width': '1.6' }),
    svg('rect', { x: '3', y: '11.5', width: '14', height: '5', rx: '1.2', stroke: 'currentColor', 'stroke-width': '1.6' }),
    svg('circle', { cx: '6', cy: '6', r: '.9', fill: 'currentColor' }), svg('circle', { cx: '6', cy: '14', r: '.9', fill: 'currentColor' })),
  import: svg('svg', { viewBox: '0 0 20 20', fill: 'none', 'aria-hidden': 'true' },
    svg('path', { d: 'M10 3v9M6.5 8.5L10 12l3.5-3.5M4 15v1.5h12V15', stroke: 'currentColor', 'stroke-width': '1.6', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' })),
};
function doorIcon(kind) {
  const node = DOOR_ICONS[kind].cloneNode(true);
  return h('span', { class: `door-icon door-icon-${kind}`, 'aria-hidden': 'true' }, node);
}

/** The first screen: two clear ways to begin. */
export function getStarted({ onAddEndpoints, onUpload }) {
  const card = (kind, title, text, ...actions) => h('section', { class: 'card start-card' },
    doorIcon(kind), h('h2', null, title), h('p', null, text), h('div', { class: 'row' }, actions));
  return h('div', { class: 'start' },
    h('div', { class: 'start-head' },
      h('h2', null, 'Welcome. Where would you like to begin?'),
      h('p', null, 'CipherHorizon shows where cryptography is used and how ready it is for the post-quantum era. There are two ways in, and you can do both.')),
    h('div', { class: 'grid two' },
      card('scan', 'Check a server’s TLS',
        'Point it at a website or any service that speaks TLS (for example example.com:443). It tests the connection, rates how ready it is for post-quantum cryptography, and tells you what to fix first.',
        button('Add endpoints', onAddEndpoints, 'primary')),
      card('inventory', 'Inventory a machine',
        'Run a short script on a computer to list its cryptographic software and certificates, then upload the result here. It shows which algorithms a quantum computer could break.',
        button('Show me how', () => collectDialog(onUpload), 'primary'), button('Upload a CBOM', onUpload))),
    h('p', { class: 'hint start-foot' }, 'Everything stays on this machine. CipherHorizon makes no outside connections except the scans you start.'));
}

/** The first screen of an empty estate: three ways to begin, of equal weight. */
export function getStartedEstate({ onAddEndpoints, onUpload, onImport }) {
  const door = (kind, title, text, ...actions) => h('section', { class: 'card start-card' },
    doorIcon(kind), h('h2', null, title), h('p', null, text), h('div', { class: 'row' }, actions));
  return h('div', { class: 'start' },
    h('div', { class: 'start-head' },
      h('h2', null, 'Build your estate'),
      h('p', null, 'CipherHorizon is a cryptographic inventory that ranks your systems for the move to post-quantum cryptography. Everything you scan, inventory or import becomes part of a system. There are three ways to add to it, and you can use all of them.')),
    h('div', { class: 'grid three' },
      door('scan', 'Scan a service', 'Point it at a website or any service that speaks TLS. It tests the connection, records the certificate and key, and says whether recorded traffic could be read later.',
        button('Add endpoints', onAddEndpoints, 'primary')),
      door('inventory', 'Inventory a machine', 'Run a short script on a computer to list its cryptographic software and certificates, then upload the result.',
        button('Show me how', () => collectDialog(onUpload), 'primary')),
      door('import', 'Import a CBOM', 'Bring in a CycloneDX CBOM from another tool. You choose which system it belongs to, and it adds facts without overwriting what was observed.',
        button('Import a CBOM', onImport, 'primary'))),
    h('p', { class: 'hint start-foot' }, 'Then tell us who owns each system and how long its data must stay secret, and it moves to the right place in the order. Everything stays on this machine; the only connections made are the scans you start.'));
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
    return { tone: 'warn', text: `${f.hndlExposed} endpoint${f.hndlExposed === 1 ? ' is' : 's are'} exposed to harvest-now-decrypt-later. Turn on a hybrid post-quantum key exchange (X25519MLKEM768) so today’s traffic stays private.`, action: { label: 'See which', href: '#/endpoints' } };
  }
  if (f.certsExpiring) {
    return { tone: 'warn', text: `${f.certsExpiring} certificate${f.certsExpiring === 1 ? ' expires' : 's expire'} within 30 days. Renew ${f.certsExpiring === 1 ? 'it' : 'them'} before ${f.certsExpiring === 1 ? 'it' : 'they'} lapse${f.certsExpiring === 1 ? 's' : ''}.`, action: { label: 'See which', href: '#/endpoints' } };
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
