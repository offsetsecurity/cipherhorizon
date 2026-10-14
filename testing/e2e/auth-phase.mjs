// Sign-in (ADR-0018), driven through the browser: first-run setup with the code from the server's
// log, an administrator adding a viewer, the viewer's forced password change, what a viewer may
// not do, a session that ends, and signing back in.
import { readFileSync } from 'node:fs';

export const ADMIN = { username: 'qa-admin', password: 'violet amber harbour lamp' };
const VIEWER = { username: 'qa-viewer', temp: 'temporary viewer phrase', password: 'the viewer own phrase' };

export function setupCode() {
  const log = process.env.E2E_SERVER_LOG ? readFileSync(process.env.E2E_SERVER_LOG, 'utf8') : '';
  const m = /[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}/.exec(log);
  return m ? m[0] : '';
}

const fill = (id, value) => `{ const i = document.getElementById(${JSON.stringify(id)}); i.value = ${JSON.stringify(value)}; i.dispatchEvent(new Event('input')); }`;

/** First run: the gate asks for the setup code; the administrator is created and signed in. */
export async function firstRun({ check, js, go, sleep, shot }) {
  await go('#/');
  await sleep(500);
  const gate = await js(`return { gated: document.body.classList.contains('gated'), title: document.querySelector('.gate-title')?.textContent,
    shell: getComputedStyle(document.querySelector('.shell')).display, focused: document.activeElement?.id }`);
  check('E2E-A.1', 'with no account, the app is replaced by first-run setup, which asks for the code from the server log',
    gate.gated && gate.title === 'Create the administrator' && gate.shell === 'none' && gate.focused === 'setup-code', JSON.stringify(gate));
  // PRD-007 REQ-ST-1: the first thing anyone sees says what the product is and who makes it.
  const panel = await js(`const v = document.querySelector('.gate-value'); return { text: v?.innerText || '',
    pillars: v ? v.querySelectorAll('.gate-pillars li').length : 0, link: v?.querySelector('a')?.href || '',
    bg: v ? getComputedStyle(v).backgroundColor : '', mark: !!v?.querySelector('.gate-mark svg') }`);
  check('E2E-B.1', 'the setup and sign-in screens carry a navy panel: Quantum-safe before it\'s urgent, three pillars, by Offset Security, the PQC readiness link',
    /Quantum-safe before it.s urgent/.test(panel.text) && panel.pillars === 3 && /TLS · SSH · post-quantum readiness/.test(panel.text)
    && /post-quantum-cryptography-readiness/.test(panel.link) && panel.bg === 'rgb(11, 20, 40)' && panel.mark, JSON.stringify(panel));
  await shot('auth-setup', { full: false });
  await js(`${fill('setup-code', 'WRONG-CODE-0000')} ${fill('setup-user', ADMIN.username)} ${fill('setup-pass', ADMIN.password)}
    document.querySelector('.gate-form').requestSubmit();`);
  await sleep(700);
  const wrong = await js(`return document.querySelector('.gate-error')?.hidden === false ? document.querySelector('.gate-error').textContent : ''`);
  check('E2E-A.2', 'a wrong setup code is refused inline, saying where the right one is', /setup code is wrong/.test(wrong) && /log/.test(wrong), wrong);
  const code = setupCode();
  await js(`${fill('setup-code', code)} document.querySelector('.gate-form').requestSubmit();`);
  await sleep(1500);
  const after = await js(`return { gated: document.body.classList.contains('gated'), h1: document.querySelector('main h1')?.textContent,
    who: document.querySelector('.acct-name')?.textContent, role: document.querySelector('.acct-role')?.textContent, cookie: document.cookie }`);
  check('E2E-A.3', 'with the code, the administrator is created and lands on the Overview, named in the sidebar; the session cookie is invisible to scripts',
    !!code && !after.gated && /Scan an endpoint/.test(after.h1 || '') && after.who === ADMIN.username && after.role === 'Administrator' && !/ch_session/.test(after.cookie),
    JSON.stringify({ code: !!code, ...after }));
}

async function signOut({ js, sleep }) {
  await js(`document.querySelector('.acct summary').click();`);
  await sleep(150);
  await js(`[...document.querySelectorAll('.acct-menu button')].find((b) => b.textContent === 'Sign out').click();`);
  await sleep(1500);
}

async function signIn({ js, sleep }, user, pass) {
  await js(`${fill('login-user', user)} ${fill('login-pass', pass)} document.querySelector('.gate-form').requestSubmit();`);
  await sleep(1500);
}

/** Accounts and roles, then the administrator signs back in for the rest of the journey. */
export async function authPhase({ check, js, go, sleep, shot, api, viewport }) {
  // An administrator adds a viewer from Users.
  await go('#/users');
  await sleep(900);
  await js(`[...document.querySelectorAll('button')].find((b) => b.textContent === 'Add an account').click();`);
  await sleep(300);
  await js(`${fill('new-user', VIEWER.username)} document.getElementById('new-role').value = 'viewer'; ${fill('new-pw', VIEWER.temp)}
    document.querySelector('.modal form').requestSubmit();`);
  await sleep(1200);
  const list = await js(`return [...document.querySelectorAll('main tbody tr')].map((r) => r.innerText.replace(/\\s+/g, ' '))`);
  check('E2E-A.4', 'an administrator adds a viewer with a temporary password from Users', list.some((t) => /qa-viewer/.test(t) && /temporary password/.test(t)), JSON.stringify(list));
  await shot('auth-users');
  // Signing out returns to the sign-in screen, and the old session no longer works.
  await signOut({ js, sleep });
  const out = await js(`return { title: document.querySelector('.gate-title')?.textContent,
    api: (await fetch('/api/v1/assets')).status }`);
  check('E2E-A.5', 'Sign out ends the session: the sign-in screen shows and the API answers 401', out.title === 'Sign in' && out.api === 401, JSON.stringify(out));
  await shot('auth-login', { full: false });
  if (viewport) {
    await viewport(390, 844, false, true);
    await sleep(400);
    const stack = await js(`const v = document.querySelector('.gate-value').getBoundingClientRect(), f = document.querySelector('.gate-panel').getBoundingClientRect();
      return { panelAbove: v.bottom <= f.top + 1, overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth }`);
    check('E2E-B.1m', 'on a phone the value panel stacks above the sign-in form, with no sideways scroll', stack.panelAbove && stack.overflow <= 1, JSON.stringify(stack));
    await shot('auth-login-mobile', { full: false });
    await viewport(1280, 900);
    await sleep(300);
  }
  // A wrong password is refused without saying whether the account exists.
  await signIn({ js, sleep }, ADMIN.username, 'not the password at all');
  const bad = await js(`return document.querySelector('.gate-error')?.textContent || ''`);
  check('E2E-A.6', 'a wrong password is refused with one generic message', bad === 'the username or password is wrong, or the account is locked for a while after repeated failed sign-ins', bad);
  // The viewer must replace the temporary password first.
  await signIn({ js, sleep }, VIEWER.username, VIEWER.temp);
  const chg = await js(`return document.querySelector('.gate-title')?.textContent`);
  check('E2E-A.7', 'an account with a temporary password must choose its own before anything else', chg === 'Choose your password', chg);
  await js(`${fill('chg-cur', VIEWER.temp)} ${fill('chg-new', VIEWER.password)} ${fill('chg-again', VIEWER.password)} document.querySelector('.gate-form').requestSubmit();`);
  await sleep(1500);
  const v = await js(`return { gated: document.body.classList.contains('gated'), role: document.querySelector('.acct-role')?.textContent,
    add: (await fetch('/api/v1/assets', { method: 'POST', headers: { 'X-Requested-With': 'cipherhorizon', 'Content-Type': 'application/json' }, body: '{"target":"example.com"}' })).status,
    read: (await fetch('/api/v1/assets')).status, users: (await fetch('/api/v1/users')).status,
    menu: [...document.querySelectorAll('.acct-menu a')].map((a) => a.textContent) }`);
  check('E2E-A.8', 'a viewer reads everything but cannot change anything or see accounts',
    !v.gated && v.role === 'Viewer' && v.read === 200 && v.add === 403 && v.users === 403 && !v.menu.includes('Users and activity'), JSON.stringify(v));
  await signOut({ js, sleep });
  await signIn({ js, sleep }, ADMIN.username, ADMIN.password);
  const back = await js(`return document.querySelector('.acct-name')?.textContent`);
  check('E2E-A.10', 'the administrator signs back in', back === ADMIN.username, back);
  // The sign-in log records all of it, and never a password.
  const log = await js(`return (await fetch('/api/v1/auth/events?limit=50')).json()`);
  check('E2E-A.9', 'the sign-in log has the setup, the failed sign-in, the new account and the password change, and no password',
    ['setup', 'login-failed', 'user-created', 'password-changed', 'logout'].every((k) => log.some((e) => e.kind === k))
    && !JSON.stringify(log).includes('violet') && !JSON.stringify(log).includes('phrase'), log.slice(0, 8).map((e) => e.kind).join(','));
}
