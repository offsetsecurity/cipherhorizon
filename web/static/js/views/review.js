// Review: the correlation queue (PRD-003 REQ-UI-5, REQ-COR-7). The product proposes which endpoint
// belongs to which system; a person decides. A proposal shows the rules that matched and the values.
import { h, clear, fmtDate } from '../dom.js';
import { api } from '../api.js';
import { badge, button, toast, skeleton, empty } from '../ui.js';
import { systemHref, strengthBadge, stateBadge, reasonDialog, validId } from '../estate-ui.js';

const RANK = { strong: 0, medium: 1, weak: 2 };

function ruleHits(l) {
  return h('ul', { class: 'why-list plain' }, (l.rules || []).map((r) => h('li', null, h('span', { class: 'why-rule' }, r.id), h('span', { class: 'why-text' }, r.detail))),
    l.note ? h('li', null, h('span', { class: 'why-text' }, l.note)) : null);
}

function linkCard(l, reload) {
  const decide = async (kind) => {
    const verb = kind === 'confirm' ? 'Confirm' : 'Reject';
    const reason = await reasonDialog(`${verb} this match`, kind === 'confirm'
      ? `${l.assetName} will join the system “${l.systemName}”. If both hold different details you entered, the join is refused and the fields are named.`
      : `${l.assetName} will stay out of “${l.systemName}”, and it will not be proposed again.`, verb);
    if (reason === null) return;
    try {
      await (kind === 'confirm' ? api.confirmLink(l.id, reason) : api.rejectLink(l.id, reason));
      toast(kind === 'confirm' ? 'Joined' : 'Rejected', 'success');
      reload();
    } catch (ex) { toast(ex.message, 'error'); }
  };
  return h('section', { class: 'card link-card' },
    h('div', { class: 'row' },
      h('h3', null, l.assetName, ' ', h('span', { class: 'muted' }, `→ ${l.systemName}`)),
      strengthBadge(l.strength), stateBadge(l.state, l.stale),
      l.competes ? badge(`${l.competes} other proposal${l.competes === 1 ? '' : 's'} for this endpoint`, 'warn') : null,
      l.ambiguous ? badge('ambiguous', 'warn', 'More than one system matches; none is joined automatically') : null),
    h('p', { class: 'hint' }, `${l.assetKind === 'host' ? 'Machine' : 'Endpoint'} ${l.assetAddress}`),
    ruleHits(l),
    l.decidedAt ? h('p', { class: 'hint' }, `${l.state} by ${l.decidedBy || 'unknown'} on ${fmtDate(l.decidedAt)}${l.reason ? `: ${l.reason}` : ''}`) : null,
    l.stale ? h('p', { class: 'callout', role: 'note' }, 'The evidence for this join is no longer observed. It has not been undone; review whether it still holds.') : null,
    h('div', { class: 'row' },
      l.state === 'proposed' ? button('Confirm', () => decide('confirm'), 'primary') : null,
      l.state !== 'rejected' ? button('Reject', () => decide('reject')) : null,
      validId(l.systemId) ? h('a', { class: 'btn btn-secondary', href: systemHref(l.systemId) }, 'Open the system') : null));
}

export async function render(root, ctx = {}) {
  root.appendChild(skeleton(4));
  const all = await api.links('all');
  clear(root);
  const reload = () => { root.replaceChildren(); return render(root, ctx).then(() => window.dispatchEvent(new Event('estate-changed'))); };
  root.appendChild(h('div', { class: 'page-head' }, ctx.embedded ? h('div') : h('div', null, h('h1', null, 'Decisions'),
    h('div', { class: 'sub' }, 'Which endpoint or machine belongs to which system: matches the product found, for you to confirm'))));

  const proposed = all.filter((l) => l.state === 'proposed').sort((a, b) => (RANK[a.strength] ?? 3) - (RANK[b.strength] ?? 3) || a.id - b.id);
  const stale = all.filter((l) => l.state === 'confirmed' && l.stale);
  const decided = all.filter((l) => l.state !== 'proposed' && !(l.state === 'confirmed' && l.stale));

  root.appendChild(h('p', { class: 'text-2' }, 'The product matches an endpoint to a machine only by three rules: the same certificate, the same name, or a name the certificate lists. A match it is sure of, from its own scans and collectors, is joined automatically and shown below as confirmed, with the reason. Everything else waits here.'));

  root.appendChild(h('h2', null, `Waiting for a decision (${proposed.length})`));
  if (proposed.length) root.appendChild(h('div', { class: 'stack' }, proposed.map((l) => linkCard(l, reload))));
  else root.appendChild(empty('Nothing waiting', 'When a scan and an upload point at the same machine but the product is not sure, the match appears here.'));

  if (stale.length) {
    root.appendChild(h('h2', { class: 'mt' }, `Evidence gone (${stale.length})`));
    root.appendChild(h('div', { class: 'stack' }, stale.map((l) => linkCard(l, reload))));
  }
  if (decided.length) {
    root.appendChild(h('h2', { class: 'mt' }, `Decided (${decided.length})`));
    root.appendChild(h('div', { class: 'stack' }, decided.map((l) => linkCard(l, reload))));
  }
  return null;
}
