// Application shell: a hash router, the navigation state and the access-token prompt.
import { h, clear } from './dom.js';
import { api, ApiError, setAuthHandler } from './api.js';
import { session, showLogin, showSetup, showChangePassword, hideGate, accountChip } from './auth.js';
import { modal, button, empty, notice, playEnter } from './ui.js';

const main = document.getElementById('main');
const modalRoot = document.getElementById('modal-root');

// The places of the menu and the detail pages under them (UX-DESIGN-005): one place per kind of
// thing; a detail page lights up its home.
const routes = [
  [/^#\/?$/, 'overview', () => import('./views/overview.js')],
  [/^#\/endpoints\/?$/, 'endpoints', () => import('./views/endpoints.js')],
  [/^#\/endpoints\/(\d+)\/?$/, 'endpoints', () => import('./views/asset.js')],
  [/^#\/machines\/?$/, 'machines', () => import('./views/hosts.js')],
  [/^#\/machines\/(\d+)\/?$/, 'machines', () => import('./views/host.js')],
  [/^#\/findings\/?$/, 'findings', () => import('./views/findings.js')],
  [/^#\/inventory\/?$/, 'inventory', () => import('./views/inventory.js')],
  [/^#\/inventory\/(algorithms|keys|certificates|protocols|software|sources)\/?$/, 'inventory', () => import('./views/inventory.js')],
  [/^#\/certificates\/([0-9a-fA-F]{64})\/?$/, 'inventory', () => import('./views/certificate.js')],
  [/^#\/systems\/?$/, 'systems', () => import('./views/systems.js')],
  [/^#\/systems\/(\d+)\/?$/, 'systems', () => import('./views/system.js')],
  [/^#\/reports\/?$/, 'reports', () => import('./views/reports.js')],
  [/^#\/about\/?$/, 'about', () => import('./views/about.js')],
  [/^#\/help\/?$/, 'help', () => import('./views/help.js')],
  [/^#\/settings\/?$/, 'settings', () => import('./views/settings.js')],
  [/^#\/account\/?$/, 'account', () => import('./views/account.js')],
  [/^#\/users\/?$/, 'users', () => import('./views/users.js')],
];

// Addresses of earlier versions keep working (UX-DESIGN-005 §6): each is replaced by its new
// place, without adding a history entry.
const redirects = [
  [/^#\/(?:assets|reports)\/(\d+)\/?$/, (m) => `#/endpoints/${m[1]}`],
  [/^#\/assets\/?$/, () => '#/endpoints'],
  [/^#\/overview\/?$/, () => '#/'],
  [/^#\/scans\/?$/, () => '#/endpoints?tab=activity'],
  [/^#\/hosts?\/(\d+)\/?$/, (m) => `#/machines/${m[1]}`],
  [/^#\/hosts?\/?$/, () => '#/machines'],
  [/^#\/imports\/?$/, () => '#/inventory/sources'],
  [/^#\/cbom\/?$/, () => '#/inventory'],
  [/^#\/certificates\/?$/, () => '#/inventory/certificates'],
  [/^#\/review\/?$/, () => '#/systems?tab=decisions'],
  [/^#\/estate\/?$/, () => '#/systems'],
];

let cleanup = null;
let generation = 0;

async function route() {
  if (document.body.classList.contains('gated')) return; // signed out: the gate is showing
  const gen = ++generation;
  if (cleanup) { try { cleanup(); } catch { /* ignore */ } cleanup = null; }
  // A modal left open across a route change (e.g. the browser's Back button while a
  // dialog is up — clicking a nav link can't do this, the overlay covers it) would
  // otherwise be stranded on top of the new page.
  clear(modalRoot);
  const [hashPath, query = ''] = (location.hash || '#/').split('?');
  // Inventory lists were tabs (?tab=…) before they became pages of their own.
  const tab = /^#\/inventory\/?$/.test(hashPath) && new URLSearchParams(query).get('tab');
  if (tab) {
    location.replace(`#/inventory/${tab === 'tls' ? 'protocols' : tab}`);
    return;
  }
  // Reports held the endpoints, the fleet's findings and the scan activity as tabs (PRD-005).
  const old = /^#\/reports\/?$/.test(hashPath) && new URLSearchParams(query).get('tab');
  if (old) {
    location.replace({ findings: '#/findings', activity: '#/endpoints?tab=activity' }[old] || '#/endpoints');
    return;
  }
  for (const [re, to] of redirects) {
    const m = re.exec(hashPath);
    if (m) {
      const target = to(m);
      location.replace(query && !target.includes('?') ? `${target}?${query}` : target);
      return;
    }
  }
  const params = new URLSearchParams(query);

  let match = null;
  for (const [re, nav, load] of routes) {
    const m = re.exec(hashPath);
    if (m) { match = { nav, load, args: m.slice(1) }; break; }
  }
  for (const a of document.querySelectorAll('#nav a, .sidefoot a[data-route]')) {
    if (match && a.dataset.route === match.nav) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  clear(main);
  if (!match) {
    main.appendChild(notice('We could not find that page', 'The address may be mistyped, or the page may have moved. Everything is reachable from the menu.', button('Go to the overview', () => { location.hash = '#/'; }, 'primary')));
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
  // Move focus to the new page, unless the page put it somewhere on purpose (the scan box).
  if (!main.contains(document.activeElement) || document.activeElement === main) main.focus({ preventScroll: true });
  refreshReviewCount();
}

// The number of match decisions waiting for a person, shown beside "Systems" in the menu.
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


// Signing in (ADR-0018). The server says whether anyone is signed in; until someone is, the gate
// replaces the application. A session that ends later (idle, signed out elsewhere) brings it back.
async function boot() {
  let st;
  try {
    st = await api.authState();
  } catch (e) {
    clear(main).appendChild(notice('Cannot reach the server', e.message, button('Try again', boot, 'primary')));
    return;
  }
  const min = st.passwordMinLength || 12;
  if (st.setupRequired) { showSetup(start, min); return; }
  if (st.loginRequired && !st.user) { showLogin(start); return; }
  start(st.user, min);
}

function start(user, min = 12) {
  if (user && user.mustChangePassword) { showChangePassword(boot, min); return; }
  session.user = user;
  hideGate();
  accountChip(document.getElementById('account-chip'), user);
  api.about().then((a) => {
    const el = document.getElementById('sidebar-version');
    if (el) el.textContent = /^\d/.test(a.version) ? `v${a.version}` : a.version;
  }).catch(() => { /* the version label is decoration: never block on it */ });
  route();
}

setAuthHandler(() => {
  if (document.body.classList.contains('gated')) return;
  session.user = null;
  clear(modalRoot);
  showLogin(start, 'Your session ended (signed out, or idle too long). Sign in again to continue.');
});

window.addEventListener('hashchange', route);
// "Scan a URL" is an action on every page, not a place (UX-DESIGN-005 principle 3).
document.getElementById('nav-scan')?.addEventListener('click', async () => {
  const { openScanDialog } = await import('./views/scan.js');
  openScanDialog();
});
boot();
export { api };
