// Endpoints: every website and TLS service you scan; a row opens its report (UX-DESIGN-005). The
// scan queue is a tab here, because it is the endpoints' activity.
import { h } from '../dom.js';
import { button } from '../ui.js';
import { openScanDialog } from './scan.js';

const TABS = [
  ['list', 'Endpoints', () => import('./assets.js')],
  ['activity', 'Scan activity', () => import('./scans.js')],
];

export async function render(root, { query }) {
  const tab = TABS.find(([k]) => k === query.get('tab')) || TABS[0];
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Endpoints'),
      h('div', { class: 'sub' }, 'Websites, TLS endpoints and SSH servers you scan. Open one for its full report.')),
    // The page's one primary action (UX-REVIEW-008 N1): the rail holds places, not actions.
    h('div', { class: 'row' }, button('Scan a URL', () => openScanDialog(), 'primary', { id: 'endpoints-scan' }))));
  root.appendChild(h('div', { class: 'tabs', role: 'tablist' }, TABS.map(([k, label]) =>
    h('a', { class: 'tab', role: 'tab', href: k === 'list' ? '#/endpoints' : `#/endpoints?tab=${k}`, 'aria-selected': String(k === tab[0]) }, label))));
  const body = h('div', { class: 'tabbody' });
  root.appendChild(body);
  const mod = await tab[2]();
  return mod.render(body, { embedded: true, query });
}
