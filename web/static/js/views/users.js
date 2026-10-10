// Users: accounts and their activity (administrators; ADR-0018, PRD-007 REQ-AC-3). An
// administrator gives a new account a temporary password, which its owner must replace at first
// sign-in. Activity lists every sign-in and every change made through the API, filterable and
// exportable.
import { h, clear, relTime, fmtDate } from '../dom.js';
import { api } from '../api.js';
import { button, toast, badge, modal, confirmDialog, crumbs } from '../ui.js';
import { session, ROLE_WORD } from '../auth.js';

const CHANGE_KIND = { endpoint: 'Endpoint', scan: 'Scan', host: 'Host', system: 'System' };

const ROLES = [['analyst', 'Analyst: scan, upload, triage, edit systems'], ['viewer', 'Viewer: read and download only'], ['admin', 'Administrator: everything, including accounts']];

const EVENT_WORD = {
  setup: 'Created the first administrator', login: 'Signed in', 'login-failed': 'Failed sign-in', locked: 'Account locked',
  logout: 'Signed out', 'password-changed': 'Changed password', 'password-change-failed': 'Failed password change',
  'password-reset': 'Password reset', 'user-created': 'Account added', 'user-updated': 'Account changed',
  'user-deleted': 'Account deleted', 'user-unlocked': 'Account unlocked', 'session-ended': 'Signed out a browser', 'setup-failed': 'Failed setup',
  'sign-in-enabled': 'Turned sign-in on', 'sign-in-disabled': 'Turned sign-in off',
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
  const tab = query.get('tab') === 'log' || query.get('tab') === 'activity' ? 'activity' : 'accounts';
  // With sign-in off the accounts are frozen (UX-REVIEW-008 D3): shown, but not changeable.
  const frozen = session.user?.kind === 'local';
  root.appendChild(crumbs([['Account', '#/account'], ['Users']]));
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Users'), h('div', { class: 'sub' }, 'Who can sign in, what each account may do, and what each one did.')),
    tab === 'accounts' && !frozen ? h('div', { class: 'row' }, button('Add an account', () => addDialog(draw), 'primary')) : h('div')));
  root.appendChild(h('div', { class: 'tabs', role: 'tablist' },
    h('a', { class: 'tab', role: 'tab', href: '#/users', 'aria-selected': String(tab === 'accounts') }, 'Accounts'),
    h('a', { class: 'tab', role: 'tab', href: '#/users?tab=activity', 'aria-selected': String(tab === 'activity') }, 'Activity')));
  if (frozen) {
    root.appendChild(h('div', { class: 'callout info' }, h('b', null, 'Sign-in is off. '),
      'Accounts are kept but not used, and cannot be changed until sign-in is on again. ', h('a', { href: '#/settings' }, 'Turn on sign-in in Settings'), '.'));
  }
  const body = h('div', { class: 'tabbody' });
  root.appendChild(body);

  // Activity: sign-ins and changes in one list, newest first, with filters and a CSV export.
  const filter = { person: query.get('person') || '', source: query.get('source') || '' };
  const filterQuery = () => {
    const q = new URLSearchParams();
    if (filter.person) q.set('person', filter.person);
    if (filter.source) q.set('source', filter.source);
    const s = q.toString();
    return s ? `?${s}` : '';
  };
  const what = (x) => {
    if (x.source === 'sign-in') return BAD.has(x.action) ? badge(EVENT_WORD[x.action] || x.action, 'bad') : (EVENT_WORD[x.action] || x.action);
    const kind = CHANGE_KIND[x.objectKind] || x.objectKind;
    return `${kind} ${x.action}`;
  };
  const objectCell = (x) => {
    if (x.source === 'sign-in') return x.username && x.username !== 'local' && !x.action.startsWith('sign-in-') ? `Account ${x.username}` : '';
    if (!x.objectId) return '';
    const href = x.objectKind === 'endpoint' ? `#/endpoints/${x.objectId}` : x.objectKind === 'system' ? `#/systems/${x.objectId}`
      : x.objectKind === 'host' ? `#/hosts/${x.objectId}` : null;
    const label = `${CHANGE_KIND[x.objectKind] || x.objectKind} ${x.objectId}`;
    return href ? h('a', { href }, label) : label;
  };

  async function drawActivity() {
    const [users, list] = await Promise.all([api.users(), api.activity(filterQuery())]);
    const person = h('select', { id: 'act-person', 'aria-label': 'Person' },
      h('option', { value: '' }, 'Everyone'),
      users.map((u) => h('option', { value: u.username, selected: u.username === filter.person }, u.displayName ? `${u.displayName} (${u.username})` : u.username)),
      h('option', { value: 'api-token', selected: filter.person === 'api-token' }, 'Automation token'));
    const source = h('select', { id: 'act-source', 'aria-label': 'Kind' },
      [['', 'Sign-ins and changes'], ['change', 'Changes only'], ['sign-in', 'Sign-ins only']].map(([v, l]) => h('option', { value: v, selected: v === filter.source }, l)));
    const apply = () => {
      filter.person = person.value;
      filter.source = source.value;
      const q = filterQuery();
      history.replaceState(null, '', `#/users?tab=activity${q ? `&${q.slice(1)}` : ''}`);
      drawActivity().catch((e) => toast(e.message, 'error'));
    };
    person.addEventListener('change', apply);
    source.addEventListener('change', apply);
    const exportBtn = button('Export CSV', () => api.download(`/api/v1/audit.csv${filterQuery()}`, 'cipherhorizon-activity.csv')
      .then(() => toast('Downloaded cipherhorizon-activity.csv', 'success')).catch((e) => toast(e.message, 'error')), 'secondary');
    clear(body).append(
      h('div', { class: 'row filterbar' }, person, source, h('span', { class: 'grow' }), exportBtn),
      list.entries.length ? h('div', { class: 'tablewrap' }, h('table', { class: 'compact activity' },
        h('thead', null, h('tr', null, ['When', 'Who', 'What', 'On', 'Detail', 'From'].map((c) => h('th', { scope: 'col' }, c)))),
        h('tbody', null, list.entries.map((x) => h('tr', null,
          h('td', { class: 'muted nowrap', title: fmtDate(x.at) }, relTime(x.at)),
          h('td', null, x.actor === 'api-token' ? 'Automation token' : x.actor === 'local' ? h('span', { class: 'muted' }, 'Anyone (sign-in off)') : (x.actor || '·')),
          h('td', null, what(x)),
          h('td', null, objectCell(x)),
          h('td', { class: 'muted' }, [x.detail, x.reason ? `reason: ${x.reason}` : ''].filter(Boolean).join('; ')),
          h('td', { class: 'muted' }, x.client || '')))))) : h('p', { class: 'hint' }, 'Nothing matches these filters yet.'),
      h('p', { class: 'hint' }, 'Every sign-in and every change made through the interface or the API is kept here. Changes are never edited or deleted; the newest 5,000 sign-in events are kept.'));
  }

  async function draw() {
    if (tab === 'activity') return drawActivity();
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
          h('td', null, me || frozen ? ROLE_WORD[u.role] : roleSel),
          h('td', null, u.disabled ? badge('disabled', 'neutral') : locked ? badge('locked', 'bad', `until ${fmtDate(u.lockedUntil)}`)
            : u.mustChangePassword ? badge('temporary password', 'warn') : badge('active', 'good')),
          h('td', { class: 'muted nowrap', title: u.lastLoginAt ? fmtDate(u.lastLoginAt) : '' }, u.lastLoginAt ? relTime(u.lastLoginAt) : 'never'),
          h('td', { class: 'rowactions' }, frozen ? null : me ? h('a', { href: '#/account', class: 'btn btn-secondary btn-sm' }, 'Your account') : [
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
    if (!frozen) body.appendChild(h('p', { class: 'hint' }, 'If every administrator is locked out, someone with access to the server can run ',
      h('code', null, 'cipherhorizon user reset-password NAME'), ' or ', h('code', null, 'cipherhorizon user unlock NAME'), ' there.'));
    return null;
  }
  await draw();
  return null;
}
