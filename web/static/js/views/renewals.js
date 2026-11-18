// Renewals (UX-DESIGN-024): every certificate the scanned endpoints serve, by the date it runs
// out. When a scan sees a newer certificate on every endpoint, an assigned renewal is marked done.
import { h, clear, fmtDay } from '../dom.js';
import { api } from '../api.js';
import { button, toast, empty, skeleton } from '../ui.js';
import { standing, assignDialog, fixHref } from '../fix-ui.js';

const METHOD = { acme: 'renews itself (ACME)', 'cert-manager': 'renews itself (cert-manager)', 'cloud-managed': 'renewed by the cloud provider',
  'ca-portal': 'renewed by hand', manual: 'renewed by hand', 'internal-ca': 'from the internal CA', vendor: 'renewed by the vendor' };
const AUTOMATIC = new Set(['acme', 'cert-manager', 'cloud-managed']);
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const LATER = 90;

function left(c) {
  if (c.daysLeft < 0) return `Ran out ${plural(-c.daysLeft, 'day')} ago.`;
  if (c.daysLeft === 0) return 'Runs out today.';
  return `${plural(c.daysLeft, 'day')} left.`;
}

function row(c, warn, repaint) {
  const urgent = c.daysLeft <= warn;
  let state;
  let action;
  if (c.fix) {
    state = h('div', { class: `fxrow-state fix-${standing(c.fix).tone}` }, `${left(c)} ${c.fix.owner || 'Assigned'}: ${standing(c.fix).text}`);
    action = h('a', { href: fixHref(c.fix.id), class: 'btn btn-secondary btn-sm' }, 'Open');
  } else if (AUTOMATIC.has(c.renewal)) {
    state = h('div', { class: `fxrow-state${urgent ? ' fix-warn' : ''}` }, `${left(c)} ${urgent ? 'It should have renewed itself by now.' : 'Nothing to do.'}`);
    action = urgent ? button('Assign', () => assignDialog({ kind: 'certificate', certificate: c.fingerprint }, { what: `${c.name}: certificate`, owner: c.owner, onDone: repaint }), 'secondary', { 'data-assign': 'certificate' }) : h('span', { class: 'small muted' }, 'nothing to do');
  } else {
    state = h('div', { class: `fxrow-state${urgent ? ' fix-bad' : ''}` }, urgent ? `${left(c)} Nobody is assigned.` : left(c));
    action = button('Assign', () => assignDialog({ kind: 'certificate', certificate: c.fingerprint }, { what: `${c.name}: certificate runs out ${fmtDay(c.notAfter)}`, owner: c.owner, onDone: repaint }),
      urgent ? 'primary' : 'secondary', { 'data-assign': 'certificate' });
  }
  return h('li', { class: 'fxrow', 'data-cert': c.fingerprint },
    h('div', { class: 'fxrow-main' }, h('a', { href: `#/certificates/${c.fingerprint}`, class: 'fxrow-title' }, c.name), state),
    h('div', { class: 'fxrow-owner' }, `${fmtDay(c.notAfter)}`, h('div', { class: 'small muted' }, `on ${plural(c.endpoints, 'endpoint')}${c.renewal ? ` · ${METHOD[c.renewal] || c.renewal}` : ''}`)),
    action);
}

/** Certificates running out in each of the next four months, as bars. */
function months(certs) {
  const now = new Date();
  const buckets = [0, 1, 2, 3].map((i) => { const d = new Date(now.getFullYear(), now.getMonth() + i, 1); return { key: `${d.getFullYear()}-${d.getMonth()}`, label: d.toLocaleString(undefined, { month: 'short' }), n: 0 }; });
  for (const c of certs) {
    const d = new Date(c.notAfter);
    const b = buckets.find((x) => x.key === `${d.getFullYear()}-${d.getMonth()}`);
    if (b) b.n++;
  }
  const max = Math.max(1, ...buckets.map((b) => b.n));
  return h('div', { class: 'renewbars', role: 'img', 'aria-label': `Certificates running out by month: ${buckets.map((b) => `${b.n} in ${b.label}`).join(', ')}` },
    buckets.map((b, i) => {
      const bar = h('div', { class: `renewbar${i === 0 && b.n ? ' renewbar-now' : ''}` });
      bar.style.height = `${b.n ? Math.max(8, Math.round((44 * b.n) / max)) : 2}px`;
      return h('div', { class: 'renewbar-col' }, bar, h('div', { class: 'small muted' }, `${b.label} · ${b.n}`));
    }));
}

export async function render(root) {
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Renewals'),
      h('div', { class: 'sub' }, 'Every certificate your endpoints serve, by the date it runs out. When a scan sees the new one on every endpoint, the renewal is marked done.'))));
  const body = h('div', { class: 'fixpage' });
  root.appendChild(body);
  body.appendChild(skeleton(5));
  let showLater = false;

  const paint = async () => {
    const d = await api.renewals();
    clear(body);
    const certs = d.certificates || [];
    if (!certs.length) {
      body.appendChild(empty('No certificates yet', 'Scan a TLS endpoint. The certificate it serves appears here with the date it runs out.',
        button('Add an endpoint', () => { location.hash = '#/endpoints'; }, 'primary')));
      return;
    }
    const soon = certs.filter((c) => c.daysLeft <= d.warnDays).length;
    const auto = certs.filter((c) => AUTOMATIC.has(c.renewal)).length;
    body.appendChild(h('section', { class: 'card fixprogress', 'aria-label': 'The next four months' },
      h('div', { class: 'fixprogress-head' },
        h('div', { class: 'fixprogress-line', id: 'renew-line' }, soon ? `${soon} ${soon === 1 ? 'runs' : 'run'} out in the next ${d.warnDays} days` : `Nothing runs out in the next ${d.warnDays} days`),
        h('div', { class: 'small muted' }, `${plural(certs.length, 'certificate')}${auto ? ` · ${auto} ${auto === 1 ? 'renews itself' : 'renew themselves'}` : ''}`)),
      months(certs)));

    if (d.unplanned && d.unplanned.length) {
      body.appendChild(h('section', { 'aria-labelledby': 'rn-odd' },
        h('h2', { id: 'rn-odd', class: 'fix-h' }, 'Changed without anyone assigned ', h('span', { class: 'fx-count' }, String(d.unplanned.length))),
        h('ul', { class: 'fxrows', id: 'renew-unplanned' }, d.unplanned.map((u) => h('li', { class: 'fxrow' },
          h('div', { class: 'fxrow-main' }, h('a', { href: `#/endpoints/${u.assetId}`, class: 'fxrow-title' }, u.name),
            h('div', { class: 'fxrow-state' }, `The scan of ${fmtDay(u.at)} found a different certificate, and nobody had been assigned a renewal.`)),
          h('div', { class: 'row' },
            button('It was expected', async () => { try { await api.expectChange({ assetId: u.assetId, toScan: u.toScan }); await paint(); } catch (e) { toast(e.message, 'error'); } }, 'secondary', { class: 'btn btn-secondary btn-sm' }),
            h('a', { class: 'btn btn-secondary btn-sm', href: `#/certificates/${u.to}` }, 'See the new one')))))));
    }

    const near = certs.filter((c) => c.daysLeft <= LATER);
    const later = certs.filter((c) => c.daysLeft > LATER);
    body.appendChild(h('section', { 'aria-labelledby': 'rn-soon' },
      h('h2', { id: 'rn-soon', class: 'fix-h' }, `Running out in the next ${LATER} days `, h('span', { class: 'fx-count' }, String(near.length))),
      near.length ? h('ul', { class: 'fxrows', id: 'renew-soon' }, near.map((c) => row(c, d.warnDays, paint))) : h('p', { class: 'muted' }, 'None.')));
    if (later.length) {
      body.appendChild(h('section', { class: 'fix-foot', 'aria-labelledby': 'rn-later' },
        h('h2', { id: 'rn-later', class: 'fix-h fix-h-sm' }, 'Later ', h('span', { class: 'fx-count' }, String(later.length))),
        button(showLater ? 'Hide them' : 'Show them', () => { showLater = !showLater; paint(); }, 'ghost', { class: 'btn btn-ghost btn-sm' })));
      if (showLater) body.appendChild(h('ul', { class: 'fxrows' }, later.map((c) => row(c, d.warnDays, paint))));
    }
  };
  await paint();
  return null;
}
