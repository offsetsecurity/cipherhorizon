// Application shell: a hash router, the navigation state and the access-token prompt.
import { h, clear } from './dom.js';
import { api, ApiError, setAuthHandler, setToken } from './api.js';
import { modal, button, empty, notice, playEnter } from './ui.js';
import { collectDialog } from './guide.js';

const main = document.getElementById('main');
const modalRoot = document.getElementById('modal-root');

const routes = [
  [/^#\/?$/, 'estate', () => import('./views/estate.js')],
  [/^#\/overview\/?$/, 'overview', () => import('./views/dashboard.js')],
  [/^#\/systems\/(\d+)\/?$/, 'estate', () => import('./views/system.js')],
  [/^#\/certificates\/?$/, 'certificates', () => import('./views/certificates.js')],
  [/^#\/certificates\/([0-9a-fA-F]{64})\/?$/, 'certificates', () => import('./views/certificate.js')],
  [/^#\/review\/?$/, 'review', () => import('./views/review.js')],
  [/^#\/imports\/?$/, 'imports', () => import('./views/imports.js')],
  [/^#\/(?:assets|endpoints)\/?$/, 'assets', () => import('./views/assets.js')],
  [/^#\/(?:assets|endpoints)\/(\d+)\/?$/, 'assets', () => import('./views/asset.js')],
  [/^#\/scans\/?$/, 'scans', () => import('./views/scans.js')],
  [/^#\/hosts?\/?$/, 'hosts', () => import('./views/hosts.js')],
  [/^#\/hosts?\/(\d+)\/?$/, 'hosts', () => import('./views/host.js')],
  [/^#\/findings\/?$/, 'findings', () => import('./views/findings.js')],
  [/^#\/cbom\/?$/, 'cbom', () => import('./views/cbom.js')],
  [/^#\/about\/?$/, 'about', () => import('./views/about.js')],
];

let cleanup = null;
let generation = 0;

async function route() {
  const gen = ++generation;
  if (cleanup) { try { cleanup(); } catch { /* ignore */ } cleanup = null; }
  // A modal left open across a route change (e.g. the browser's Back button while a
  // dialog is up — clicking a nav link can't do this, the overlay covers it) would
  // otherwise be stranded on top of the new page.
  clear(modalRoot);
  const [hashPath, query = ''] = (location.hash || '#/').split('?');
  const params = new URLSearchParams(query);

  let match = null;
  for (const [re, nav, load] of routes) {
    const m = re.exec(hashPath);
    if (m) { match = { nav, load, args: m.slice(1) }; break; }
  }
  for (const a of document.querySelectorAll('#nav a')) {
    if (match && a.dataset.route === match.nav) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  clear(main);
  if (!match) {
    main.appendChild(notice('We could not find that page', 'The address may be mistyped, or the page may have moved. Everything is reachable from the menu.', button('Go to the estate', () => { location.hash = '#/'; }, 'primary')));
    return;
  }
  try {
    const mod = await match.load();
    if (gen !== generation) return;
    const fn = await mod.render(main, { args: match.args, query: params });
    if (gen !== generation) { if (typeof fn === 'function') fn(); return; }
    cleanup = typeof fn === 'function' ? fn : null;
    playEnter(main);
  } catch (err) {
    if (gen !== generation) return;
    if (err instanceof ApiError && err.status === 401) return; // the token prompt is showing
    clear(main).appendChild(h('div', { class: 'card', role: 'alert' },
      h('h2', null, 'Something went wrong'),
      h('p', null, err instanceof ApiError ? err.message : `Unexpected error: ${err.message}`),
      button('Try again', route, 'primary')));
  }
  main.focus({ preventScroll: true });
  refreshReviewCount();
}

// The number of proposed matches waiting for a person, shown beside "Review" in the menu.
async function refreshReviewCount() {
  const el = document.getElementById('nav-review-count');
  if (!el) return;
  try {
    const n = (await api.links('proposed')).length;
    el.textContent = String(n);
    el.hidden = n === 0;
    el.setAttribute('aria-label', `${n} waiting`);
  } catch { /* the badge is decoration: never block on it */ }
}
window.addEventListener('estate-changed', refreshReviewCount);

document.getElementById('nav-collector')?.addEventListener('click', () => collectDialog(null));

setAuthHandler(() => {
  if (document.querySelector('.modal[aria-label="Access token"]')) return;
  modal('Access token', (close) => {
    const input = h('input', { type: 'password', autocomplete: 'off', 'aria-label': 'Access token' });
    const form = h('form', { class: 'modal-body', onsubmit: (e) => { e.preventDefault(); setToken(input.value.trim()); close(); route(); } },
      h('p', null, 'This server requires an access token. It is kept only for this browser tab.'),
      input, h('div', { class: 'row end' }, h('button', { type: 'submit', class: 'btn btn-primary' }, 'Continue')));
    return form;
  });
});

window.addEventListener('hashchange', route);
api.about().then((a) => {
  const el = document.getElementById('sidebar-version');
  if (el) el.textContent = /^\d/.test(a.version) ? `v${a.version}` : a.version;
}).catch(() => { /* the version label is decoration: never block on it */ });
route();
export { api };
