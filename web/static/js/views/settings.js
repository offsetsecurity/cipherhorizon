// Settings (UX-REVIEW-008 S3): who can use this server, and how it is configured. Sign-in is off
// by default, so one person can scan right away; a team turns it on here, which creates the first
// administrator in the same step.
import { h, clear } from '../dom.js';
import { api } from '../api.js';
import { button, toast, confirmDialog, badge, modal } from '../ui.js';

/** Turning sign-in off (UX-REVIEW-008 D2, D3, D5): say what happens, and ask for the password. */
function turnOffDialog(accounts, onDone) {
  modal('Turn off sign-in?', (close) => {
    const pw = h('input', { type: 'password', id: 'off-pw', autocomplete: 'current-password', required: true });
    const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
    setTimeout(() => pw.focus(), 0);
    return h('form', { class: 'modal-body', onsubmit: async (e) => {
      e.preventDefault();
      err.hidden = true;
      try {
        await api.setSignIn({ enabled: false, password: pw.value });
        close();
        onDone();
      } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    } }, err,
    h('p', null, 'Anyone who can reach this server will be able to use it, with every right. Specifically:'),
    h('ul', { class: 'consequences' },
      h('li', null, h('b', null, 'Everyone is signed out. '), 'Every session ends, yours included.'),
      h('li', null, h('b', null, `The ${accounts === 1 ? 'account is' : `${accounts} accounts are`} kept, and frozen. `),
        'Names, roles and passwords stay as they are and work again when sign-in is turned back on. Until then they cannot be added, changed or removed.'),
      h('li', null, h('b', null, 'History keeps its names. '), 'What people did while signed in stays attributed to them. What anyone does while sign-in is off is recorded as anonymous, with the address it came from.'),
      h('li', null, h('b', null, 'Coming back: '), 'turning sign-in on again asks everyone, you included, to sign in with their account.')),
    h('label', { for: 'off-pw' }, 'Your password, to confirm'), pw,
    h('div', { class: 'row end' }, button('Cancel', close), h('button', { type: 'submit', class: 'btn btn-danger' }, 'Turn off sign-in')));
  });
}

const LOCK_WORD = { on: 'on', off: 'off' };

export async function render(root) {
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Settings'), h('div', { class: 'sub' }, 'Who can use this server, and how it is configured.'))));
  const body = h('div', { class: 'stack' });
  root.appendChild(body);

  async function draw() {
    const [st, auth] = await Promise.all([api.settings(), api.authState()]);
    const s = st.signIn;
    clear(body).append(signInCard(s, auth), serverCard(st.server));
  }

  function signInCard(s, auth) {
    const state = s.required ? badge('On', 'good') : badge('Off', 'neutral');
    const card = h('section', { class: 'card settings-card', 'aria-labelledby': 'set-signin-h' },
      h('div', { class: 'settings-head' }, h('h2', { id: 'set-signin-h' }, 'Sign-in'), state));
    if (!s.required) {
      card.append(h('p', null, 'Anyone who can reach this server can use it, with every right. That suits one person on their own machine. ',
        'Turn sign-in on to give people their own accounts and roles (administrator, analyst, viewer) and to record who did what.'));
      if (s.lockedBy) {
        card.append(h('p', { class: 'hint' }, `Sign-in is set to ${LOCK_WORD[s.lockedBy]} by the server’s command line (`, h('code', null, `--sign-in ${s.lockedBy}`), '), so it cannot be changed here.'));
        return card;
      }
      if (s.accounts > 0) {
        card.append(h('p', { class: 'hint' }, `${s.accounts} account${s.accounts === 1 ? ' is' : 's are'} kept from when sign-in was on, frozen until it is on again. `,
          'What people did then stays attributed to them; what anyone does now is recorded as anonymous, with the address it came from. ',
          'Turning sign-in on asks everyone, including you, to sign in with an account.'),
          h('div', { class: 'row' }, button('Turn on sign-in', async () => {
            if (!(await confirmDialog('Turn on sign-in?', 'Everyone, including you, will need to sign in with an existing account.', 'Turn on'))) return;
            try { await api.setSignIn({ enabled: true }); location.reload(); } catch (e) { toast(e.message, 'error'); }
          }, 'primary')));
        return card;
      }
      const user = h('input', { type: 'text', id: 'si-user', autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', required: true });
      const name = h('input', { type: 'text', id: 'si-name', autocomplete: 'name' });
      const pass = h('input', { type: 'password', id: 'si-pass', autocomplete: 'new-password', required: true, minlength: auth.passwordMinLength });
      const err = h('div', { class: 'callout bad', role: 'alert', hidden: true });
      card.append(h('h3', null, 'Turn on sign-in'),
        h('p', { class: 'text-2' }, 'The first account is the administrator: it adds the others under Users. You will be signed in with it straight away.'),
        h('form', { class: 'form-narrow', onsubmit: async (e) => {
          e.preventDefault();
          err.hidden = true;
          try {
            await api.setSignIn({ enabled: true, username: user.value.trim(), displayName: name.value.trim(), password: pass.value });
            toast('Sign-in is on. You are signed in as the administrator.', 'success');
            setTimeout(() => location.reload(), 600);
          } catch (ex) { err.textContent = ex.message; err.hidden = false; }
        } }, err,
        h('label', { for: 'si-user' }, 'Administrator username'), user,
        h('label', { for: 'si-name' }, 'Name (optional)'), name,
        h('label', { for: 'si-pass' }, 'Password'), pass,
        h('p', { class: 'hint' }, `At least ${auth.passwordMinLength} characters. A phrase of a few unrelated words is strong and easy to remember.`),
        h('div', { class: 'row' }, h('button', { type: 'submit', class: 'btn btn-primary' }, 'Turn on sign-in'))));
      return card;
    }
    card.append(h('p', null, `Every request needs an account: ${s.accounts} account${s.accounts === 1 ? '' : 's'}. Sessions end after ${auth.sessionIdleMinutes} minutes without activity.`),
      h('div', { class: 'row' }, h('a', { class: 'btn btn-secondary', href: '#/users' }, 'Users and activity'),
        s.canTurnOff ? button('Turn off sign-in', () => turnOffDialog(s.accounts, () => {
          toast('Sign-in is off. Everyone was signed out; accounts are kept.');
          setTimeout(() => location.reload(), 700);
        }), 'secondary') : null));
    if (s.lockedBy) {
      card.append(h('p', { class: 'hint' }, 'Set by the server’s command line (', h('code', null, `--sign-in ${s.lockedBy}`), '), so it cannot be changed here.'));
    } else if (!s.canTurnOff) {
      card.append(h('p', { class: 'hint' }, 'This server is reachable from the network, so sign-in stays on. To run it open, restart it with ', h('code', null, '--open-network'), '.'));
    }
    return card;
  }

  function serverCard(v) {
    const scope = (v.scanScope || []).length ? `only ${v.scanScope.join(', ')}` : 'any routable address except loopback, link-local and cloud-metadata ones';
    const rows = [
      ['Version', `${v.version} (evaluation rules ${v.evalVersion})`],
      ['What may be scanned', scope, '--scan-allow'],
      ['This machine (loopback)', v.allowLoopback ? 'may be scanned' : 'may not be scanned', '--allow-loopback'],
      ['HTTP check (HSTS)', v.httpChecks ? 'on: one GET / after the handshake' : 'off', '--http-checks'],
      ['CRL lookups', v.crlLookups ? 'on: each certificate’s CRL is fetched from its CA (plain HTTP)' : 'off: revocation is known only from stapled OCSP', '--revocation'],
      ['Automation token', v.automationToken ? 'accepted for scripts and CI' : 'not configured', '--token'],
      ['Scans at once', String(v.maxConcurrentScans), '--max-concurrent-scans'],
      ['History kept', `the last ${v.retentionPerAsset} scans of each endpoint`],
      ['Sessions', `end after ${v.sessionIdleMinutes} minutes idle, or ${v.sessionMaxHours} hours`, '--session-idle, --session-max'],
    ];
    return h('section', { class: 'card', 'aria-labelledby': 'set-server-h' },
      h('h2', { id: 'set-server-h' }, 'This server'),
      h('p', { class: 'text-2' }, 'Set on the server’s command line when it starts.'),
      h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
        h('thead', null, h('tr', null, ['Setting', 'Value', 'Option'].map((c) => h('th', { scope: 'col' }, c)))),
        h('tbody', null, rows.map(([k, val, flag]) => h('tr', null, h('td', null, k), h('td', null, val), h('td', { class: 'muted' }, flag ? h('code', null, flag) : '')))))));
  }

  await draw();
  return null;
}
