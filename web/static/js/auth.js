// Signing in (ADR-0018): the screens shown instead of the application until someone is signed
// in, first-run setup, and the change of a temporary password. The server decides everything;
// these screens only ask and show its answer.
import { h, clear, brandMark } from './dom.js';
import { api, ApiError } from './api.js';

const gate = () => document.getElementById('gate');

// What the product is, said once where everyone sees it first (PRD-007 REQ-ST-1): the Offset
// headline, the three pillars, and who makes it.
export const PILLARS = [
  ['Post-quantum readiness', 'A level from L0 to L4 for every endpoint, and which ones would leak recorded traffic to a future quantum computer.'],
  ['A TLS scanner that shows its work', 'Every protocol, cipher suite and group, every check passed or failed, each with its source.'],
  ['An inventory you can hand over', 'One CycloneDX CBOM for endpoints and machines, and reports an auditor accepts.'],
];
export const PQC_SERVICE = 'https://offsetsecurity.net/post-quantum-cryptography-readiness.html';

const VALUE = () => h('aside', { class: 'gate-value', 'aria-label': 'About CipherHorizon' },
  h('div', { class: 'gate-lockup' }, h('span', { class: 'gate-mark', 'aria-hidden': 'true' }, brandMark('color')),
    h('span', null, h('span', { class: 'gate-name' }, 'CipherHorizon'), h('span', { class: 'gate-by' }, 'TLS and post-quantum scanner'))),
  h('div', { class: 'gate-value-body' },
    h('p', { class: 'eyebrow eyebrow-navy' }, 'Post-quantum readiness · TLS scanner · CBOM'),
    h('p', { class: 'gate-headline' }, 'Quantum-safe before it\'s urgent.'),
    h('ul', { class: 'gate-pillars' }, PILLARS.map(([t, d]) => h('li', null, h('b', null, t), h('span', null, d))))),
  h('p', { class: 'gate-credit' }, 'Self-hosted and open source, from ',
    h('a', { href: PQC_SERVICE, target: '_blank', rel: 'noopener' }, 'Offset Security\'s post-quantum readiness practice'), '.'));

function field(id, label, attrs, hint) {
  const input = h('input', { id, name: id, ...attrs });
  return { input, node: h('div', { class: 'gate-field' }, h('label', { for: id }, label), input, hint ? h('p', { class: 'gate-hint', id: `${id}-hint` }, hint) : null) };
}

/** A form that shows the server's refusal inline and keeps its button honest while waiting. */
function gateForm(title, lede, fields, submitLabel, onSubmit, extra) {
  const err = h('div', { class: 'gate-error', role: 'alert', hidden: true });
  const submit = h('button', { type: 'submit', class: 'btn btn-primary gate-submit' }, submitLabel);
  const form = h('form', { class: 'gate-form', novalidate: true, onsubmit: async (e) => {
    e.preventDefault();
    err.hidden = true;
    submit.disabled = true;
    const was = submit.textContent;
    submit.textContent = 'Please wait…';
    try {
      await onSubmit();
    } catch (ex) {
      err.textContent = ex instanceof ApiError ? ex.message : `Something went wrong: ${ex.message}`;
      err.hidden = false;
      submit.disabled = false;
      submit.textContent = was;
      const first = form.querySelector('input[type=password]') || form.querySelector('input');
      if (first) first.focus();
    }
  } }, h('h1', { class: 'gate-title' }, title), lede ? h('p', { class: 'gate-lede' }, lede) : null, err, fields.map((f) => f.node), submit, extra || null);
  return form;
}

function show(node) {
  document.body.classList.add('gated');
  const g = gate();
  clear(g).append(h('div', { class: 'gate-split' }, VALUE(),
    h('div', { class: 'gate-side' }, h('main', { class: 'gate-panel', id: 'gate-main' }, node,
      h('p', { class: 'gate-foot' }, 'A session ends after a period without activity. Sign out when you leave a shared computer.')))));
  g.hidden = false;
  const first = g.querySelector('input');
  if (first) first.focus();
}

export function hideGate() {
  document.body.classList.remove('gated');
  const g = gate();
  clear(g);
  g.hidden = true;
}

/** The sign-in screen. why says why it appeared (a session that ended). */
export function showLogin(onDone, why) {
  const user = field('login-user', 'Username', { type: 'text', autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', required: true });
  const pass = field('login-pass', 'Password', { type: 'password', autocomplete: 'current-password', required: true });
  show(gateForm('Sign in', why || 'Sign in to see your scans, inventory and reports.', [user, pass], 'Sign in', async () => {
    const r = await api.login(user.input.value.trim(), pass.input.value);
    pass.input.value = '';
    onDone(r.user);
  }, h('p', { class: 'gate-hint' }, 'Forgot your password? Ask your administrator to reset it.')));
}

/** First run: create the administrator with the code printed in the server's log. */
export function showSetup(onDone, minLen) {
  const code = field('setup-code', 'Setup code', { type: 'text', autocomplete: 'one-time-code', spellcheck: 'false', placeholder: 'XXXX-XXXX-XXXX', required: true },
    'Printed in the server\'s log when it started. It works once.');
  const user = field('setup-user', 'Administrator username', { type: 'text', autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', required: true });
  const name = field('setup-name', 'Your name (optional)', { type: 'text', autocomplete: 'name' });
  const pass = field('setup-pass', 'Password', { type: 'password', autocomplete: 'new-password', required: true, minlength: minLen },
    `At least ${minLen} characters. A phrase of a few unrelated words is strong and easy to remember.`);
  show(gateForm('Create the administrator', 'No account exists yet. The first account administers the others.', [code, user, name, pass], 'Create and sign in', async () => {
    const r = await api.setup({ code: code.input.value, username: user.input.value.trim(), displayName: name.input.value.trim(), password: pass.input.value });
    onDone(r.user);
  }));
}

/** A temporary password must be replaced before anything else. */
export function showChangePassword(onDone, minLen) {
  const cur = field('chg-cur', 'Temporary password', { type: 'password', autocomplete: 'current-password', required: true });
  const next = field('chg-new', 'New password', { type: 'password', autocomplete: 'new-password', required: true, minlength: minLen },
    `At least ${minLen} characters, and not containing your username.`);
  const again = field('chg-again', 'New password again', { type: 'password', autocomplete: 'new-password', required: true });
  show(gateForm('Choose your password', 'An administrator set a temporary password for this account. Replace it to continue.', [cur, next, again], 'Save and continue', async () => {
    if (next.input.value !== again.input.value) throw new ApiError(400, 'The two new passwords are different.');
    await api.changePassword(cur.input.value, next.input.value);
    onDone();
  }, h('p', { class: 'gate-hint' }, h('a', { href: '#', onclick: async (e) => { e.preventDefault(); await api.logout().catch(() => {}); location.reload(); } }, 'Sign out instead'))));
}

/** Who is signed in, for views that adapt to the role (null before sign-in). */
export const session = { user: null };

export const ROLE_WORD = { admin: 'Administrator', analyst: 'Analyst', viewer: 'Viewer' };
export const canChange = () => !session.user || session.user.role !== 'viewer';
export const isAdmin = () => !!session.user && session.user.role === 'admin';

const initials = (u) => (u.displayName || u.username).split(/[\s._@-]+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join('');

/** The account control at the foot of the sidebar: who is signed in, and a menu. */
export function accountChip(root, user) {
  if (!root) return;
  clear(root);
  if (!user || user.kind === 'local') {
    root.appendChild(h('p', { class: 'acct-local' }, 'Sign-in is off. ', h('a', { href: '#/settings' }, 'Turn it on')));
    return;
  }
  const items = [
    h('a', { href: '#/account', role: 'menuitem' }, 'Account and password'),
    user.role === 'admin' ? h('a', { href: '#/users', role: 'menuitem' }, 'Users and activity') : null,
    h('button', { type: 'button', role: 'menuitem', onclick: async () => {
      try { await api.logout(); } catch { /* signed out either way */ }
      // Nothing may render once the session is gone: mark the page signed out first, then reload.
      session.user = null;
      document.body.classList.add('gated');
      location.hash = '#/';
      location.reload();
    } }, 'Sign out'),
  ];
  const menu = h('details', { class: 'acct' },
    h('summary', { class: 'acct-chip', 'aria-label': `Account: ${user.displayName || user.username}` },
      h('span', { class: 'acct-avatar', 'aria-hidden': 'true' }, initials(user)),
      h('span', { class: 'acct-who' }, h('span', { class: 'acct-name' }, user.displayName || user.username), h('span', { class: 'acct-role' }, ROLE_WORD[user.role] || user.role))),
    h('div', { class: 'acct-menu', role: 'menu' }, items));
  menu.addEventListener('click', (e) => { if (e.target.closest('a')) menu.open = false; });
  document.addEventListener('click', (e) => { if (menu.open && !menu.contains(e.target)) menu.open = false; });
  root.appendChild(menu);
}
