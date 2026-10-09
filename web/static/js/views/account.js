// Account: who you are signed in as, your password, and every browser signed in to your account,
// any of which you can sign out (ADR-0018).
import { h, clear, relTime, fmtDate } from '../dom.js';
import { api } from '../api.js';
import { button, toast, badge } from '../ui.js';
import { session, ROLE_WORD } from '../auth.js';

const ROLE_CAN = {
  admin: 'Everything, including adding accounts and reading the activity log.',
  analyst: 'Scan, upload inventories, import CBOMs, triage findings and edit systems.',
  viewer: 'Read and download everything; change nothing.',
};

function browserOf(ua) {
  const b = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'A browser';
  const os = /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Linux/.test(ua) ? 'Linux' : '';
  return os ? `${b} on ${os}` : b;
}

export async function render(root) {
  const u = session.user;
  root.appendChild(h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Account'),
    h('div', { class: 'sub' }, 'Your sign-in, your password and where you are signed in.'))));
  if (!u || u.kind !== 'session') {
    root.appendChild(h('section', { class: 'card' }, h('p', null, 'This server runs without sign-in (local mode), so there is no account to manage.')));
    return null;
  }
  root.appendChild(h('section', { class: 'card', 'aria-labelledby': 'acct-h' },
    h('h2', { id: 'acct-h' }, u.displayName || u.username),
    h('dl', { class: 'facts' },
      h('div', null, h('dt', null, 'Username'), h('dd', null, u.username)),
      h('div', null, h('dt', null, 'Role'), h('dd', null, ROLE_WORD[u.role] || u.role, h('span', { class: 'muted' }, ` · ${ROLE_CAN[u.role] || ''}`))))));

  // Change password.
  const cur = h('input', { type: 'password', id: 'acct-cur', autocomplete: 'current-password' });
  const next = h('input', { type: 'password', id: 'acct-new', autocomplete: 'new-password' });
  const again = h('input', { type: 'password', id: 'acct-again', autocomplete: 'new-password' });
  const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
  const sessionsBox = h('div');
  root.appendChild(h('section', { class: 'card', 'aria-labelledby': 'pw-h' },
    h('h2', { id: 'pw-h' }, 'Change password'),
    h('p', { class: 'muted' }, 'Changing it signs you out everywhere else.'),
    h('form', { class: 'form-narrow', onsubmit: async (e) => {
      e.preventDefault();
      err.hidden = true;
      try {
        if (next.value !== again.value) throw new Error('The two new passwords are different.');
        await api.changePassword(cur.value, next.value);
        cur.value = next.value = again.value = '';
        toast('Password changed. Your other sessions are signed out.', 'success');
        drawSessions();
      } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    } }, err,
    h('label', { for: 'acct-cur' }, 'Current password'), cur,
    h('label', { for: 'acct-new' }, 'New password'), next,
    h('p', { class: 'hint' }, 'At least 12 characters, not containing your username. A phrase of a few unrelated words works well.'),
    h('label', { for: 'acct-again' }, 'New password again'), again,
    h('div', { class: 'row' }, h('button', { type: 'submit', class: 'btn btn-primary' }, 'Change password')))));

  root.appendChild(h('section', { class: 'card', 'aria-labelledby': 'sess-h' }, h('h2', { id: 'sess-h' }, 'Where you are signed in'), sessionsBox));
  const drawSessions = async () => {
    const list = await api.sessions().catch(() => []);
    clear(sessionsBox).appendChild(h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
      h('thead', null, h('tr', null, ['Browser', 'From', 'Signed in', 'Last active', ''].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, list.map((x) => h('tr', null,
        h('td', null, browserOf(x.userAgent), x.current ? [' ', badge('this browser', 'good')] : null),
        h('td', { class: 'muted' }, x.client),
        h('td', { class: 'muted', title: fmtDate(x.createdAt) }, relTime(x.createdAt)),
        h('td', { class: 'muted', title: fmtDate(x.lastSeenAt) }, relTime(x.lastSeenAt)),
        h('td', null, x.current ? null : button('Sign out', async () => {
          try { await api.endSession(x.id); toast('Signed out that browser', 'success'); drawSessions(); } catch (e) { toast(e.message, 'error'); }
        }, 'secondary', { class: 'btn btn-secondary btn-sm' }))))))));
  };
  await drawSessions();
  return null;
}
