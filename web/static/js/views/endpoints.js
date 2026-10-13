// TLS endpoints and SSH servers: a page per protocol (UX-DESIGN-007 §2), each a list whose row opens
// its report, and the scan queue as a tab, because it is that protocol's activity.
import { h } from '../dom.js';
import { button } from '../ui.js';
import { openScanDialog } from './scan.js';
import { openAddDialog, PLACES } from './assets.js';

const TABS = [
  ['list', () => import('./assets.js')],
  ['activity', () => import('./scans.js')],
];

const COPY = {
  tls: { sub: 'Websites and the TLS services behind mail, directories and databases. Open one for its full report.', list: 'TLS endpoints' },
  ssh: { sub: 'Servers you reach over SSH, judged against the CipherHorizon SSH baseline 2026. Nothing logs in.', list: 'SSH servers' },
};

// show opens a protocol's list, or draws it again when it is already open (setting the same hash
// fires no hashchange, so a list would otherwise miss what was just added).
const show = (hash) => {
  if (location.hash === hash) window.dispatchEvent(new HashChangeEvent('hashchange'));
  else location.hash = hash;
};

export async function render(root, { query, protocol = 'tls' }) {
  const place = PLACES[protocol];
  const copy = COPY[protocol];
  const tab = TABS.find(([k]) => k === query.get('tab')) || TABS[0];
  // The page's one primary action (UX-REVIEW-008 N1): the rail holds places, not actions.
  const primary = protocol === 'ssh'
    ? button('Add SSH servers', () => openAddDialog(() => show(place.list), { protocol }), 'primary', { id: 'ssh-add' })
    : button('Scan a URL', () => openScanDialog(), 'primary', { id: 'endpoints-scan' });
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, place.many), h('div', { class: 'sub' }, copy.sub)),
    h('div', { class: 'row' }, primary)));
  root.appendChild(h('div', { class: 'tabs', role: 'tablist' }, [['list', copy.list], ['activity', 'Scan activity']].map(([k, label]) =>
    h('a', { class: 'tab', role: 'tab', href: k === 'list' ? place.list : `${place.list}?tab=${k}`, 'aria-selected': String(k === tab[0]) }, label))));
  const body = h('div', { class: 'tabbody' });
  root.appendChild(body);
  const mod = await tab[1]();
  return mod.render(body, { embedded: true, query, protocol });
}
