// Users: accounts and the sign-in log (administrators; ADR-0018). An administrator gives a new
// account a temporary password, which its owner must replace at first sign-in.
import { h, clear, relTime, fmtDate } from '../dom.js';
import { api } from '../api.js';
import { button, toast, badge, modal, confirmDialog, crumbs } from '../ui.js';
import { session, ROLE_WORD } from '../auth.js';

const ROLES = [['analyst', 'Analyst: scan, upload, triage, edit systems'], ['viewer', 'Viewer: read and download only'], ['admin', 'Administrator: everything, including accounts']];

const EVENT_WORD = {
  setup: 'Created the first administrator', login: 'Signed in', 'login-failed': 'Failed sign-in', locked: 'Account locked',
  logout: 'Signed out', 'password-changed': 'Changed password', 'password-change-failed': 'Failed password change',
  'password-reset': 'Password reset', 'user-created': 'Account added', 'user-updated': 'Account changed',
  'user-deleted': 'Account deleted', 'user-unlocked': 'Account unlocked', 'session-ended': 'Signed out a browser', 'setup-failed': 'Failed setup',
};
const BAD = new Set(['login-failed', 'locked', 'password-change-failed', 'setup-failed']);

/** A temporary password: 4 words-worth of random letters, easy to read out once. */
function tempPassword() {
  const a = 'abcdefghijkmnpqrstuvwxyz23456789';
  const b = new Uint8Array(20);
  crypto.getRandomValues(b);
  return [...b].map((x) => a[x % a.length]).join('').replace(/(.{5})(?=.)/g, '$1-');
}

function passwordDialog(title, intro, submitLabel, onSubmit) {
  modal(title, (close) => {
    const pw = h('input', { type: 'text', id: 'tmp-pw', value: tempPassword(), autocomplete: 'off', spellcheck: 'false' });
    const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
    return h('form', { class: 'modal-body', onsubmit: async (e) => {
      e.preventDefault();
      try { await onSubmit(pw.value); close(); } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    } }, err, h('p', null, intro),
    h('label', { for: 'tmp-pw' }, 'Temporary password'), pw,
    h('p', { class: 'hint' }, 'Give it to the person privately. They must replace it when they first sign in; until then they can do nothing else.'),
    h('div', { class: 'row end' }, button('Cancel', close), h('button', { type: 'submit', class: 'btn btn-primary' }, submitLabel)));
  });
}

function addDialog(onDone) {
  modal('Add an account', (close) => {
    const user = h('input', { type: 'text', id: 'new-user', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false' });
    const name = h('input', { type: 'text', id: 'new-name', autocomplete: 'off' });
    const role = h('select', { id: 'new-role' }, ROLES.map(([v, l]) => h('option', { value: v }, l)));
    const pw = h('input', { type: 'text', id: 'new-pw', value: tempPassword(), autocomplete: 'off', spellcheck: 'false' });
    const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
    setTimeout(() => user.focus(), 0);
    return h('form', { class: 'modal-body', onsubmit: async (e) => {
      e.preventDefault();
      try {
        await api.addUser({ username: user.value.trim(), displayName: name.value.trim(), role: role.value, password: pw.value });
        toast(`Added ${user.value.trim()}`, 'success');
        close();
        onDone();
      } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    } }, err,
    h('label', { for: 'new-user' }, 'Username'), user,
    h('p', { class: 'hint' }, '3 to 64 letters, digits and . _ - @ (an e-mail address works).'),
    h('label', { for: 'new-name' }, 'Name (optional)'), name,
    h('label', { for: 'new-role' }, 'Role'), role,
    h('label', { for: 'new-pw' }, 'Temporary password'), pw,
    h('p', { class: 'hint' }, 'Give it to the person privately; they replace it at first sign-in.'),
    h('div', { class: 'row end' }, button('Cancel', close), h('button', { type: 'submit', class: 'btn btn-primary' }, 'Add account')));
  });
}

export async function render(root, { query }) {
  const tab = query.get('tab') === 'log' ? 'log' : 'accounts';
  root.appendChild(crumbs([['Account', '#/account'], ['Users']]));
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Users'), h('div', { class: 'sub' }, 'Who can sign in, what each account may do, and every sign-in.')),
    tab === 'accounts' ? h('div', { class: 'row' }, button('Add an account', () => addDialog(draw), 'primary')) : h('div')));
  root.appendChild(h('div', { class: 'tabs', role: 'tablist' },
    h('a', { class: 'tab', role: 'tab', href: '#/users', 'aria-selected': String(tab === 'accounts') }, 'Accounts'),
    h('a', { class: 'tab', role: 'tab', href: '#/users?tab=log', 'aria-selected': String(tab === 'log') }, 'Sign-in log')));
  const body = h('div', { class: 'tabbody' });
  root.appendChild(body);

  async function drawLog() {
    const ev = await api.authEvents(300);
    clear(body).appendChild(h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
      h('thead', null, h('tr', null, ['When', 'What', 'Account', 'By', 'From', 'Detail'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, ev.map((x) => h('tr', null,
        h('td', { class: 'muted nowrap', title: fmtDate(x.at) }, relTime(x.at)),
        h('td', null, BAD.has(x.kind) ? badge(EVENT_WORD[x.kind] || x.kind, 'bad') : EVENT_WORD[x.kind] || x.kind),
        h('td', null, x.username), h('td', { class: 'muted' }, x.actor), h('td', { class: 'muted' }, x.client), h('td', { class: 'muted' }, x.detail)))))));
  }

  async function draw() {
    if (tab === 'log') return drawLog();
    const users = await api.users();
    const act = (label, fn, kind = 'secondary') => button(label, async () => {
      try { await fn(); draw(); } catch (e) { toast(e.message, 'error'); }
    }, kind, { class: `btn btn-${kind} btn-sm` });
    clear(body).appendChild(h('div', { class: 'tablewrap' }, h('table', null,
      h('thead', null, h('tr', null, ['Account', 'Role', 'State', 'Last sign-in', ''].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, users.map((u) => {
        const me = session.user && session.user.id === u.id;
        const locked = u.lockedUntil && new Date(u.lockedUntil) > new Date();
        const roleSel = h('select', { 'aria-label': `Role of ${u.username}`, onchange: async (e) => {
          try { await api.patchUser(u.id, { role: e.target.value }); toast(`${u.username} is now ${ROLE_WORD[e.target.value]}`, 'success'); } catch (ex) { toast(ex.message, 'error'); }
          draw();
        } }, ROLES.map(([v]) => h('option', { value: v, selected: v === u.role }, ROLE_WORD[v])));
        return h('tr', null,
          h('td', { class: 'namecell' }, h('b', null, u.displayName || u.username), u.displayName || me ? h('div', { class: 'sub' }, u.displayName ? u.username : '', u.displayName && me ? ' · ' : '', me ? 'you' : '') : null),
          h('td', null, me ? ROLE_WORD[u.role] : roleSel),
          h('td', null, u.disabled ? badge('disabled', 'neutral') : locked ? badge('locked', 'bad', `until ${fmtDate(u.lockedUntil)}`)
            : u.mustChangePassword ? badge('temporary password', 'warn') : badge('active', 'good')),
          h('td', { class: 'muted nowrap', title: u.lastLoginAt ? fmtDate(u.lastLoginAt) : '' }, u.lastLoginAt ? relTime(u.lastLoginAt) : 'never'),
          h('td', { class: 'rowactions' }, me ? h('a', { href: '#/account', class: 'btn btn-secondary btn-sm' }, 'Your account') : [
            locked ? act('Unlock', () => api.unlockUser(u.id)) : null, ' ',
            button('Reset password', () => passwordDialog(`Reset the password of ${u.username}`, 'This signs the account out everywhere.', 'Reset password', async (pw) => {
              await api.resetPassword(u.id, pw); toast('Password reset', 'success'); draw();
            }), 'secondary', { class: 'btn btn-secondary btn-sm' }), ' ',
            act(u.disabled ? 'Enable' : 'Disable', () => api.patchUser(u.id, { disabled: !u.disabled })), ' ',
            button('Delete', async () => {
              if (!(await confirmDialog(`Delete ${u.username}?`, 'The account and its sessions are removed. What it did stays in the history and the sign-in log.', 'Delete'))) return;
              try { await api.deleteUser(u.id); toast('Account deleted', 'success'); draw(); } catch (e) { toast(e.message, 'error'); }
            }, 'secondary', { class: 'btn btn-secondary btn-sm' })]));
      })))));
    // Recovery for the case no administrator can sign in: only people who can see this page need it.
    body.appendChild(h('p', { class: 'hint' }, 'If every administrator is locked out, someone with access to the server can run ',
      h('code', null, 'cipherhorizon user reset-password NAME'), ' or ', h('code', null, 'cipherhorizon user unlock NAME'), ' there.'));
    return null;
  }
  await draw();
  return null;
}
