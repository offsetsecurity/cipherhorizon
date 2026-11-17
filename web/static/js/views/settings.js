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
    const [st, auth, life, integ, sent] = await Promise.all([api.settings(), api.authState(), api.lifecycleSettings().catch(() => null),
      api.integrations().catch(() => []), api.notifications().catch(() => [])]);
    const s = st.signIn;
    clear(body).append(...[signInCard(s, auth), scanningCard(st.scanning, auth), discoveryCard(st.discovery, auth),
      life ? notificationsCard(life, sent) : null, integrationsCard(integ), serverCard(st.server)].filter(Boolean));
  }

  // Notifications (PRD-023): the lifecycle monitor's windows and where it sends each event, once.
  function notificationsCard(life, sent) {
    const ls = { ...life.settings };
    const num = (id, val, min, max) => h('input', { type: 'number', id, value: String(val), min: String(min), max: String(max), class: 'num-input' });
    const warn = num('life-warn', ls.expiryWarnDays, 1, 365);
    const crit = num('life-crit', ls.expiryCriticalDays, 0, 365);
    const soon = num('life-soon', ls.dueSoonDays, 0, 60);
    const url = h('input', { type: 'url', id: 'life-url', value: ls.webhookUrl || '', placeholder: 'https://hooks.example.com/cipherhorizon', autocomplete: 'off', spellcheck: 'false' });
    const fmt = h('select', { id: 'life-format' }, h('option', { value: 'json', selected: ls.webhookFormat !== 'chat' }, 'JSON (for scripts and ticketing)'),
      h('option', { value: 'chat', selected: ls.webhookFormat === 'chat' }, 'Chat message (Slack, Microsoft Teams incoming webhook)'));
    const env = h('input', { type: 'text', id: 'life-env', value: ls.webhookSecretEnv || '', placeholder: 'CH_WEBHOOK_SECRET', autocomplete: 'off', spellcheck: 'false' });
    const chosen = new Set(ls.events && ls.events.length ? ls.events : life.kinds.map((k) => k.kind));
    const kinds = life.kinds.map((k) => {
      const box = h('input', { type: 'checkbox', id: `life-ev-${k.kind}`, checked: chosen.has(k.kind), onchange: (e) => { if (e.target.checked) chosen.add(k.kind); else chosen.delete(k.kind); } });
      return h('div', { class: 'setrow' }, h('div', { class: 'setrow-switch' }, box),
        h('div', { class: 'setrow-text' }, h('label', { for: `life-ev-${k.kind}`, class: 'setrow-label' }, k.title), h('p', { class: 'setrow-help' }, k.about)));
    });
    const recent = (sent || []).slice(0, 8);
    const STATUS = { sent: ['sent', 'good'], pending: ['pending', 'warn'], failed: ['failed', 'bad'], 'not-sent': ['not sent', 'neutral'] };
    return h('section', { class: 'card settings-card', id: 'set-notify', 'aria-labelledby': 'set-notify-h' },
      h('div', { class: 'settings-head' }, h('h2', { id: 'set-notify-h' }, 'Notifications'),
        badge(ls.webhookUrl ? 'webhook set' : 'not sending', ls.webhookUrl ? 'good' : 'neutral')),
      h('p', null, 'The lifecycle monitor looks at the work and the certificates every few minutes (', h('code', null, '--monitor-every'), ') and lists what needs a person on ',
        h('a', { href: '#/work?tab=attention' }, 'Work, Needs attention'), '. With a webhook it also sends each event once.'),
      h('div', { class: 'form-3col' },
        h('div', null, h('label', { for: 'life-warn' }, 'Certificate expiry warning (days)'), warn),
        h('div', null, h('label', { for: 'life-crit' }, 'Critical when within (days)'), crit),
        h('div', null, h('label', { for: 'life-soon' }, 'Work due soon (days)'), soon)),
      h('label', { for: 'life-url' }, 'Webhook address'), url,
      h('div', { class: 'form-2col' },
        h('div', null, h('label', { for: 'life-format' }, 'Format'), fmt),
        h('div', null, h('label', { for: 'life-env' }, 'Signing secret: environment variable'), env)),
      h('p', { class: 'hint' }, 'The secret is never stored here: name the server’s environment variable that holds it, and each message carries ',
        h('code', null, 'X-CipherHorizon-Signature: sha256=…'), ' over its body. ', life.secretSet ? h('b', null, 'That variable is set.') : 'No secret is in use.',
        ' Webhooks obey the same address rules as scans: no cloud-metadata or link-local address.'),
      h('h3', { class: 'discover-h3' }, 'Send'), h('div', { class: 'setrows' }, kinds),
      h('div', { class: 'row' },
        button('Save', async () => {
          try {
            await api.putLifecycleSettings({ expiryWarnDays: Number(warn.value), expiryCriticalDays: Number(crit.value), dueSoonDays: Number(soon.value),
              webhookUrl: url.value.trim(), webhookFormat: fmt.value, webhookSecretEnv: env.value.trim(),
              events: chosen.size === life.kinds.length ? [] : [...chosen] });
            toast('Notification settings saved.', 'success');
            draw();
          } catch (e) { toast(e.message, 'error'); }
        }, 'primary', { id: 'life-save' }),
        button('Send a test message', async () => {
          try { await api.testWebhook(); toast('Test message sent.', 'success'); } catch (e) { toast(e.message, 'error'); }
        }, 'secondary', { disabled: !ls.webhookUrl }),
        button('Check now', async () => {
          try { const r = await api.lifecycleCheck(); toast(`${r.events} events, ${r.new} new, ${r.delivered} sent${r.failed ? `, ${r.failed} failed` : ''}.`, r.failed ? 'error' : 'success'); draw(); } catch (e) { toast(e.message, 'error'); }
        }, 'secondary', { id: 'life-check' })),
      recent.length ? h('div', { class: 'tablewrap mt' }, h('table', { class: 'compact' },
        h('thead', null, h('tr', null, ['Event', 'Status', 'Seen'].map((c) => h('th', { scope: 'col' }, c)))),
        h('tbody', null, recent.map((n) => h('tr', null,
          h('td', null, n.title, n.lastError ? h('div', { class: 'small text-bad' }, n.lastError) : null),
          h('td', null, badge(...(STATUS[n.status] || [n.status, 'neutral']))),
          h('td', { class: 'nowrap small' }, new Date(n.lastSeen).toLocaleString())))))) : null);
  }

  // Integrations (PRD-023 M3): what this build can talk to, and what is only planned.
  function integrationsCard(list) {
    if (!list || !list.length) return null;
    const avail = list.filter((c) => c.status === 'available');
    const planned = list.filter((c) => c.status !== 'available');
    const row = (c) => h('tr', { 'data-integration': c.id },
      h('td', null, h('b', null, c.name), h('div', { class: 'small muted' }, c.summary)),
      h('td', { class: 'small' }, (c.categories || []).join(', ')),
      h('td', { class: 'small' }, (c.capabilities || []).join('; ')),
      h('td', null, c.status === 'available' ? badge(c.configured ? 'in use' : 'available', c.configured ? 'good' : 'neutral') : badge('planned', 'none'),
        c.health ? h('div', { class: 'small muted' }, c.health) : null));
    const table = (rows) => h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
      h('thead', null, h('tr', null, ['Integration', 'Kind', 'Can', 'State'].map((c) => h('th', { scope: 'col' }, c)))), h('tbody', null, rows.map(row))));
    return h('section', { class: 'card settings-card', id: 'set-integrations', 'aria-labelledby': 'set-int-h' },
      h('div', { class: 'settings-head' }, h('h2', { id: 'set-int-h' }, 'Integrations')),
      h('p', null, 'What this server can talk to. A connector acts only on work a person moved forward, never verifies its own change, and holds credentials only as references to the server’s environment.'),
      table(avail),
      h('details', { class: 'mt' }, h('summary', null, `Planned (${planned.length}): evaluated, not built`),
        h('p', { class: 'hint' }, 'Listed so the roadmap is visible. None of these is available in this version.'), table(planned)));
  }

  // Scanning (0.5.1): the options every scan runs with, changed here and applied to the next scan.
  // The command line only sets the starting values.
  function scanningCard(sc, auth) {
    const canEdit = !auth?.required || auth?.me?.role === 'admin' || auth?.role === 'admin';
    const OPTS = [
      ['httpChecks', 'HTTP check (HSTS)', 'After the TLS handshake, send one plain GET / and read the Strict-Transport-Security header. The only check that sends more than a handshake: one request, headers only, no redirect followed. Off, the HTTP security area reads not checked.'],
      ['crlLookups', 'CRL lookups', 'After the handshakes, fetch the CRL each certificate on the served chain names, from the CA’s CRL server (plain HTTP, at most 16 MiB, cached until its next update) and report whether the certificate is revoked. Off, revocation is known only from a stapled OCSP response. OCSP responders are never contacted.'],
      ['crlPrivate', 'CRL servers on private addresses', 'Let CRL lookups reach private (RFC 1918, unique-local) and loopback addresses: an internal CA’s CRL server. Off, such URLs are refused, because any scanned server can name one.'],
    ];
    const state = Object.fromEntries(OPTS.map(([k]) => [k, sc[k]]));
    const save = async () => {
      try {
        const r = await api.setScanning({ httpChecks: state.httpChecks ? 'on' : 'off', crlLookups: state.crlLookups ? 'on' : 'off', crlPrivate: state.crlPrivate ? 'on' : 'off' });
        toast('Scanning settings saved: they apply to the next scan.', 'success');
        Object.assign(sc, r);
        draw();
      } catch (e) { toast(e.message, 'error'); }
    };
    const reset = async () => {
      try { await api.setScanning({ httpChecks: 'default', crlLookups: 'default', crlPrivate: 'default' }); toast('Back to the command line’s values.', 'success'); draw(); } catch (e) { toast(e.message, 'error'); }
    };
    const rows = OPTS.map(([k, label, text]) => {
      const box = h('input', { type: 'checkbox', id: `scan-${k}`, checked: !!state[k], disabled: !canEdit || (k === 'crlPrivate' && !state.crlLookups),
        onchange: (e) => { state[k] = e.target.checked; if (k === 'crlLookups') { const p = card.querySelector('#scan-crlPrivate'); if (p) p.disabled = !e.target.checked; } } });
      const overridden = (sc.overridden || []).includes(k);
      return h('div', { class: 'setrow' },
        h('div', { class: 'setrow-switch' }, box),
        h('div', { class: 'setrow-text' },
          h('label', { for: `scan-${k}`, class: 'setrow-label' }, label, ' ', badge(sc[k] ? 'on' : 'off', sc[k] ? 'good' : 'neutral'),
            overridden ? h('span', { class: 'hint', title: 'Set here; the command line said otherwise' }, ` · set here (started ${sc.defaults[k] ? 'on' : 'off'})`) : null),
          h('p', { class: 'setrow-help' }, text)));
    });
    const card = h('section', { class: 'card settings-card', 'aria-labelledby': 'set-scan-h' },
      h('div', { class: 'settings-head' }, h('h2', { id: 'set-scan-h' }, 'Scanning')),
      h('p', null, 'What every scan does beyond the TLS handshakes. A change applies to the next scan; results already stored keep what their scan did. ',
        'The server’s command line sets the starting values (', h('code', null, '--http-checks'), ', ', h('code', null, '--revocation'), ', ', h('code', null, '--revocation-private'), ').'),
      h('div', { class: 'setrows' }, rows),
      canEdit ? h('div', { class: 'row' }, button('Save', save, 'primary'), (sc.overridden || []).length ? button('Use the command line’s values', reset, 'secondary') : null)
        : h('p', { class: 'hint' }, 'Only an administrator can change these.'));
    return card;
  }

  // Finding names from a domain: the one source that tells an outside service which domain is
  // being asked about is off until an administrator turns it on (PRD-022 D2).
  function discoveryCard(dv, auth) {
    if (!dv || !dv.available) return null;
    const canEdit = !auth?.required || auth?.me?.role === 'admin' || auth?.role === 'admin';
    const on = !!dv.certificateTransparency;
    const box = h('input', { type: 'checkbox', id: 'disc-ct', checked: on, disabled: !canEdit });
    return h('section', { class: 'card settings-card', 'aria-labelledby': 'set-disc-h' },
      h('div', { class: 'settings-head' }, h('h2', { id: 'set-disc-h' }, 'Finding names from a domain')),
      h('p', null, 'What ', h('a', { href: '#/discover' }, 'Find from a domain'), ' may use to list the host names under a domain. Reading the domain’s DNS records and the names this server already holds is always allowed.'),
      h('div', { class: 'setrows' }, h('div', { class: 'setrow' },
        h('div', { class: 'setrow-switch' }, box),
        h('div', { class: 'setrow-text' },
          h('label', { for: 'disc-ct', class: 'setrow-label' }, 'Search certificate logs', ' ', badge(on ? 'on' : 'off', on ? 'good' : 'neutral')),
          h('p', { class: 'setrow-help' }, `Ask ${dv.service} for every name that ever got a public certificate under the domain. It usually finds the most names. `,
            h('strong', null, `Each search sends the domain name to ${dv.service}, an outside service.`), ' Off, this server contacts nothing but DNS and the hosts it finds.')))),
      canEdit ? h('div', { class: 'row' }, button('Save', async () => {
        try {
          await api.setDiscovery({ certificateTransparency: box.checked ? 'on' : 'off' });
          toast(box.checked ? 'Certificate log search is on.' : 'Certificate log search is off.', 'success');
          draw();
        } catch (e) { toast(e.message, 'error'); }
      }, 'primary')) : h('p', { class: 'hint' }, 'Only an administrator can change this.'));
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
