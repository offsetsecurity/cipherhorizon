// Systems: group endpoints and machines, set owners, and see which to move to post-quantum
// first; the match decisions are a tab here, not a page of their own (PRD-005 REQ-SYS).
import { h } from '../dom.js';
import { api } from '../api.js';

const TABS = [
  ['order', 'Migration order', () => import('./estate.js')],
  ['decisions', 'Decisions', () => import('./review.js')],
];

export async function render(root, { query }) {
  const tab = TABS.find(([k]) => k === query.get('tab')) || TABS[0];
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Systems'),
      h('div', { class: 'sub' }, 'Group endpoints and machines, set owners, and see which to move to post-quantum first'))));
  const count = h('span', { class: 'navcount', hidden: true });
  root.appendChild(h('div', { class: 'tabs', role: 'tablist' }, TABS.map(([k, label]) =>
    h('a', { class: 'tab', role: 'tab', href: k === 'order' ? '#/systems' : `#/systems?tab=${k}`, 'aria-selected': String(k === tab[0]) },
      label, k === 'decisions' ? [' ', count] : null))));
  api.links('proposed').then((l) => { count.textContent = String(l.length); count.hidden = l.length === 0; }).catch(() => {});
  const body = h('div', { class: 'tabbody' });
  root.appendChild(body);
  const mod = await tab[2]();
  return mod.render(body, { embedded: true, query });
}
