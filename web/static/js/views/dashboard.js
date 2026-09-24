// The dashboard: the fleet's post-quantum readiness and posture at a glance.
import { h, clear, relTime, fmtDate } from '../dom.js';
import { api } from '../api.js';
import { donut, trendBars, barList, sizeBars, LEVELS, levelClass, levelName } from '../charts.js';
import { levelBadge, bandBadge, BAND_ORDER, bandTone, statusPill, progressBar, button, empty, toast, badge, sevBadge, skeleton, countUp } from '../ui.js';
import { openAddDialog } from './assets.js';

function kpi(label, value, kind = '', hint) {
  const n = h('div', { class: 'n' }, String(value));
  countUp(n, label, value);
  return h('div', { class: `card kpi ${kind}`, title: hint }, n, h('div', { class: 'l' }, label));
}

export async function render(root) {
  let timer = null;
  let stopped = false;
  root.appendChild(skeleton(5));

  const paint = (f, hosts, priority) => {
    clear(root);
    root.appendChild(h('div', { class: 'page-head' },
      h('div', null, h('h1', null, 'Dashboard'),
        h('div', { class: 'sub' }, 'Crypto posture across your TLS endpoints and hosts')),
      h('div', { class: 'row' },
        button('Add endpoints', () => openAddDialog(() => draw()), 'primary'),
        f.assets ? button('Scan all', async () => {
          try {
            const r = await api.scanMany({ all: true });
            toast(`${r.queued} scan(s) queued${r.alreadyActive ? `, ${r.alreadyActive} already running` : ''}.`, 'success');
            draw();
          } catch (e) { toast(e.message, 'error'); }
        }) : null)));

    if (!f.assets && !hosts.length) {
      root.appendChild(empty('Start by adding the endpoints you want to assess',
        'Add one or many TLS endpoints (host or host:port). Scan them to see how ready each is for post-quantum cryptography, how well it is configured, and what to fix first.',
        button('Add endpoints', () => openAddDialog(() => draw()), 'primary')));
      return;
    }

    const hostsVulnerable = hosts.reduce((n, h2) => n + (h2.summary ? h2.summary.vulnerable : 0), 0);
    root.appendChild(h('div', { class: 'grid kpis' },
      kpi('Endpoints', f.assets),
      kpi('Scanned', `${f.scanned} / ${f.assets}`),
      kpi('Exposed to harvest-now-decrypt-later', f.hndlExposed, f.hndlExposed ? 'alert' : 'good',
        'Endpoints whose recorded traffic a future quantum computer could read'),
      kpi('Critical / high findings', `${f.critical} / ${f.high}`, f.critical ? 'alert' : ''),
      kpi('Certificates expiring ≤ 30 days', f.certsExpiring, f.certsExpiring ? 'alert' : 'good'),
      kpi('Hosts (package inventory)', hosts.length, hostsVulnerable ? 'alert' : '', 'Machines reporting a CBOM, separate from the TLS endpoints above')));

    if (priority.length) root.appendChild(priorityCard(priority));

    root.appendChild(h('div', { class: 'grid two' },
      readinessCard(f), trendCard(f)));
    root.appendChild(h('div', { class: 'grid two' }, hygieneCard(f), attentionCard(f)));
    root.appendChild(recentCard(f));
    sizeBars(root);
  };

  const draw = async () => {
    if (stopped) return;
    try {
      const [f, hosts, priority] = await Promise.all([
        api.summary(14),
        api.hosts().catch(() => []),
        api.fleetFindings('?status=new').catch(() => []),
      ]);
      if (!stopped) {
        paint(f, hosts, priority.slice(0, 5));
        const active = (f.recent || []).some((s) => s.status === 'queued' || s.status === 'running');
        timer = setTimeout(draw, active ? 1500 : 6000);
      }
    } catch (e) {
      if (!stopped) toast(e.message, 'error');
      timer = setTimeout(draw, 8000);
    }
  };
  await draw();
  return () => { stopped = true; clearTimeout(timer); };
}

function readinessCard(f) {
  const total = f.scanned;
  const legend = h('ul', { class: 'legend' }, LEVELS.map(({ level, name, short }) => {
    const n = f.readiness[level] || 0;
    if (!n && level < 0) return null;
    return h('li', null, h('span', { class: `swatch sw${level < 0 ? 'u' : level}`, 'aria-hidden': 'true' }),
      h('span', null, h('b', null, short), ` ${name}`), h('span', { class: 'muted' }, ` · ${n}`));
  }));
  return h('section', { class: 'card' },
    h('h2', null, 'PQC readiness'),
    total ? h('div', { class: 'donutrow' }, donut(f.readiness, total), legend)
      : h('p', { class: 'muted' }, 'Scan an endpoint to see its readiness.'),
    h('p', { class: 'hint' }, 'A readiness level is this product’s own scale. ', h('a', { href: '#/about' }, 'What do the levels mean?')));
}

function trendCard(f) {
  const has = f.trend.some((p) => Object.keys(p.levels).length);
  return h('section', { class: 'card' }, h('h2', null, 'Readiness over the last 14 days'),
    has ? trendBars(f.trend) : h('p', { class: 'muted' }, 'The trend appears after the first completed scan.'),
    h('p', { class: 'hint' }, 'Each column shows every endpoint’s level as of the end of that day.'));
}

function hygieneCard(f) {
  const entries = BAND_ORDER.filter((b) => f.bands[b]).map((b) => [b, f.bands[b]]);
  return h('section', { class: 'card' }, h('h2', null, 'TLS hygiene'),
    entries.length ? barList(entries, (b) => `tone-${bandTone(b)}`) : h('p', { class: 'muted' }, 'No rated endpoints yet.'),
    h('p', { class: 'hint' }, 'A 0 to 100 score of how well an endpoint is configured, worked out from its cited findings. ',
      h('a', { href: '#/about' }, 'How is it worked out?')));
}

function priorityCard(priority) {
  return h('section', { class: 'card' },
    h('div', { class: 'row' }, h('h2', null, 'Top priority findings'), h('a', { href: '#/findings' }, 'All findings')),
    h('p', { class: 'hint' }, 'Ranked across every TLS endpoint and host, worst first — not yet acknowledged or accepted.'),
    h('ul', { class: 'priority-list' }, priority.map((pfind) => h('li', null,
      pfind.severity ? sevBadge(pfind.severity) : badge('quantum-vulnerable', 'warn'),
      h('span', { class: 'pf-title' }, pfind.title),
      h('a', { href: `#/${pfind.assetKind === 'host' ? 'hosts' : 'assets'}/${pfind.assetId}`, class: 'pf-asset' }, pfind.assetName)))));
}

function attentionCard(f) {
  return h('section', { class: 'card' }, h('h2', null, 'Needs attention'),
    f.needsAttention.length ? h('ul', { class: 'stack' },
      f.needsAttention.map((a) => h('li', null,
        h('div', { class: 'row' }, h('a', { href: `#/assets/${a.assetId}`, class: 'namecell' }, h('b', null, a.name)),
          levelBadge(a.readinessLevel, false), bandBadge(a.band, a.score)),
        h('div', { class: 'muted' }, `${a.address} · ${a.why}`)))) : h('p', { class: 'muted' }, 'Nothing needs attention. 🎉'));
}

function recentCard(f) {
  return h('section', { class: 'card' }, h('div', { class: 'row' },
    h('h2', null, 'Recent scans'), h('a', { href: '#/scans' }, 'All scans')),
    f.recent.length ? h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
      h('thead', null, h('tr', null, ['Endpoint', 'Status', 'Readiness', 'TLS hygiene', 'When'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, f.recent.map((s) => h('tr', null,
        h('td', { class: 'namecell' }, h('a', { href: `#/assets/${s.assetId}` }, s.assetName), h('div', { class: 'sub' }, s.assetAddress)),
        h('td', null, statusPill(s.status), s.status === 'running' ? progressBar(s.progressPct) : null),
        h('td', null, s.status === 'done' ? levelBadge(s.readinessLevel) : badge('–', 'none')),
        h('td', null, s.status === 'done' ? bandBadge(s.band, s.score) : badge('–', 'none')),
        h('td', { class: 'muted', title: fmtDate(s.finishedAt || s.queuedAt) }, relTime(s.finishedAt || s.queuedAt)))))))
      : h('p', { class: 'muted' }, 'No scans yet.'));
}
