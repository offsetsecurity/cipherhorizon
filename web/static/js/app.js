// Application shell: a hash router, the navigation state and the access-token prompt.
import { h, clear } from './dom.js';
import { api, ApiError, setAuthHandler, setToken } from './api.js';
import { modal, button, empty } from './ui.js';

const main = document.getElementById('main');

const routes = [
  [/^#\/?$/, 'dashboard', () => import('./views/dashboard.js')],
  [/^#\/assets\/?$/, 'assets', () => import('./views/assets.js')],
  [/^#\/assets\/(\d+)\/?$/, 'assets', () => import('./views/asset.js')],
  [/^#\/scans\/?$/, 'scans', () => import('./views/scans.js')],
  [/^#\/hosts\/?$/, 'hosts', () => import('./views/hosts.js')],
  [/^#\/hosts\/(\d+)\/?$/, 'hosts', () => import('./views/host.js')],
  [/^#\/about\/?$/, 'about', () => import('./views/about.js')],
];

let cleanup = null;
let generation = 0;

async function route() {
  const gen = ++generation;
  if (cleanup) { try { cleanup(); } catch { /* ignore */ } cleanup = null; }
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
    main.appendChild(empty('Page not found', 'That address does not exist.', button('Go to the dashboard', () => { location.hash = '#/'; }, 'primary')));
    return;
  }
  try {
    const mod = await match.load();
    if (gen !== generation) return;
    const fn = await mod.render(main, { args: match.args, query: params });
    if (gen !== generation) { if (typeof fn === 'function') fn(); return; }
    cleanup = typeof fn === 'function' ? fn : null;
  } catch (err) {
    if (gen !== generation) return;
    if (err instanceof ApiError && err.status === 401) return; // the token prompt is showing
    clear(main).appendChild(h('div', { class: 'card', role: 'alert' },
      h('h2', null, 'Something went wrong'),
      h('p', null, err instanceof ApiError ? err.message : `Unexpected error: ${err.message}`),
      button('Try again', route, 'primary')));
  }
  main.focus({ preventScroll: true });
}

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
route();
export { api };
