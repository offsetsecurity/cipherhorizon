// The shared instruments (UX-DESIGN-011 §2, PRD-013 REQ-VIS-1). Every quantity the product shows is
// drawn with one of these, so one instrument means one thing on every page: a bits bar on the
// Configuration, the certificate page, the Inventory and the SSH report has one scale and one set
// of colours. Each one carries its meaning in words for assistive technology (role="img" and an
// aria-label) and its source in the tooltip. They are built with the textContent-only DOM builder
// and position through SVG attributes or the CSSOM, never a style attribute (the CSP forbids those).
import { h, svg } from './dom.js';

/** The strength bands, in bits (PRD-010 §2): below 80 broken, 80 to 111 weak, 112 to 127
 *  acceptable, 128 and up strong. The scale ends at 256, the most NIST assigns. */
export const BANDS = [[0, 80, 'broken'], [80, 112, 'weak'], [112, 128, 'acceptable'], [128, 256, 'strong']];
const SCALE = 256;

/** A strength in words: "128 bits", "112 bits, disallowed", "broken", "not rated". */
export function strengthWords(st) {
  if (!st) return 'not rated';
  if (st.status === 'rated') return `${st.bits} bits`;
  if (st.status === 'disallowed') return `${st.bits} bits, disallowed`;
  if (st.status === 'broken') return 'broken';
  return 'not rated';
}

/** The band a strength falls in: broken, weak, acceptable, strong, or na (not rated). */
export function bandOf(st) {
  if (!st) return 'na';
  if (st.status === 'broken') return 'broken';
  if (st.status !== 'rated' && st.status !== 'disallowed') return 'na';
  const b = BANDS.find(([lo, hi]) => st.bits >= lo && st.bits < hi);
  return b ? b[2] : 'strong';
}

/**
 * A bits bar: the 0 to 256 track with its four bands, filled to the value in its band's colour, the
 * value in words beside it. A broken status fills the track in red; not rated leaves it empty.
 * opts.weakest rings it; opts.name names it for the aria-label.
 */
export function bitsBar(st, opts = {}) {
  const band = bandOf(st);
  const words = strengthWords(st);
  const track = svg('svg', { class: 'bb-track', viewBox: `0 0 ${SCALE} 10`, preserveAspectRatio: 'none', 'aria-hidden': 'true', focusable: 'false' });
  for (const [lo, hi, b] of BANDS) track.appendChild(svg('rect', { x: lo, y: 0, width: hi - lo, height: 10, class: `bb-band bb-band-${b}` }));
  if (band === 'broken') track.appendChild(svg('rect', { x: 0, y: 2, width: SCALE, height: 6, class: 'bb-fill bb-fill-broken' }));
  else if (band !== 'na') track.appendChild(svg('rect', { x: 0, y: 2, width: Math.min(st.bits, SCALE), height: 6, rx: 1, class: `bb-fill bb-fill-${band}` }));
  if (opts.weakest) track.appendChild(svg('rect', { x: 0.5, y: 0.5, width: SCALE - 1, height: 9, class: 'bb-ring', 'vector-effect': 'non-scaling-stroke' }));
  return h('span', { class: `bitsbar${opts.weakest ? ' is-weakest' : ''}`, role: 'img', title: (st && st.basis) || null,
    'aria-label': `${opts.name ? `${opts.name}: ` : ''}${words}${opts.weakest ? ', the weakest' : ''}` },
  track, h('span', { class: `bb-value bb-value-${band}` }, words, opts.weakest ? h('span', { class: 'bb-weakest' }, 'weakest') : null));
}

/** The tick row above a column of bits bars. */
export function bitsAxis() {
  const axis = h('span', { class: 'bb-axis', 'aria-hidden': 'true' });
  for (const t of [0, 80, 128, 192, 256]) { // 112 is a band edge on the bar; its label would touch 128
    const tick = h('span', { class: `bb-tick${t === 0 ? ' first' : t === SCALE ? ' last' : ''}` }, String(t));
    tick.style.left = `${(t / SCALE) * 100}%`;
    axis.appendChild(tick);
  }
  return h('span', { class: 'bb-axis-row' }, axis, h('span', { class: 'bb-value bb-axis-unit' }, 'bits'));
}

const WORDS = { strong: 'Strong', acceptable: 'Acceptable', weak: 'Weak', insecure: 'Insecure' };
/** A suite's word (PRD-010): the only place it is shown. */
export function strengthChip(word, title) {
  const w = String(word || '').toLowerCase();
  return h('span', { class: `schip schip-${WORDS[w] ? w : 'na'}`, title: title || null }, WORDS[w] || 'Not rated');
}

/** One heat cell of a suite's part: its bits on its band's tint, ringed when weakest; "·" when the
 *  suite has no such part (an AEAD suite has no MAC). */
export function partCell(part, weakest, absent) {
  if (!part) {
    return absent === 'unused' ? h('span', { class: 'pcell pcell-none', title: 'Not used by this suite (an AEAD cipher authenticates itself)' }, '·')
      : h('span', { class: 'pcell pcell-na', title: absent || 'Not measured' }, '?', h('span', { class: 'sr-only' }, ' not measured'));
  }
  const band = bandOf(part.strength);
  const st = part.strength;
  const text = band === 'broken' ? '✕' : band === 'na' ? '?' : String(st.bits);
  return h('span', { class: `pcell pcell-${band}${weakest ? ' is-weakest' : ''}`, title: `${part.name}: ${strengthWords(st)}${weakest ? ' (the weakest part)' : ''}${st && st.basis ? `. ${st.basis}` : ''}` },
    text, h('span', { class: 'sr-only' }, ` ${part.name}${weakest ? ', weakest' : ''}`));
}

const SHIELD = 'M8 1.5 13.5 3.5v4.2c0 3.2-2.3 5.6-5.5 6.8-3.2-1.2-5.5-3.6-5.5-6.8V3.5Z';
/** The post-quantum verdict as a glyph: a shield with a check, a shield with a cross, a question
 *  mark when the source classified it as unknown, or a dot when there is no verdict to give. */
export function pqGlyph(status) {
  if (status === 'quantum-safe' || status === 'quantum-vulnerable') {
    const safe = status === 'quantum-safe';
    return svg('svg', { class: `pqg ${safe ? 'pqg-safe' : 'pqg-vuln'}`, viewBox: '0 0 16 16', width: 18, height: 18, role: 'img', 'aria-label': safe ? 'Quantum-safe' : 'Quantum-vulnerable' },
      svg('title', null, safe ? 'Quantum-safe' : 'Quantum-vulnerable: a quantum computer breaks it'),
      svg('path', { d: SHIELD }), svg('path', { d: safe ? 'm5.5 8 1.8 1.8 3.2-3.4' : 'm6 6 4 4M10 6l-4 4' }));
  }
  if (status === 'unknown') return h('span', { class: 'pqg pqg-na', title: 'Not classified: no cited post-quantum status for this algorithm' }, '?', h('span', { class: 'sr-only' }, 'not classified'));
  return h('span', { class: 'pqg pqg-na', title: 'No post-quantum verdict for this algorithm' }, '·', h('span', { class: 'sr-only' }, 'no post-quantum verdict'));
}

const GLYPH = { good: '✓', attention: '!', problem: '✕', na: '·' };
/** A state as a tile: a glyph, a name and a one-line state, in one of four tones; detail is the
 *  raw evidence it was read from (a header, a URL), shown as code. */
export function statusTile(name, state, tone = 'na', href, onclick, detail) {
  const tag = href ? 'a' : 'div';
  return h(tag, { class: `stile stile-${tone}`, href: href || null, onclick: onclick || null },
    h('span', { class: 'stile-head' }, h('span', { class: 'stile-glyph', 'aria-hidden': 'true' }, GLYPH[tone] || '·'), h('b', null, name),
      h('span', { class: 'sr-only' }, ` (${{ good: 'good', attention: 'needs attention', problem: 'problem', na: 'does not apply' }[tone]})`)),
    h('span', { class: 'stile-state' }, state),
    detail ? h('code', { class: 'stile-detail' }, detail) : null);
}

/** Days used against a lifetime, with today marked. */
export function lifetimeBar(notBefore, notAfter, now = Date.now()) {
  const from = Date.parse(notBefore), to = Date.parse(notAfter);
  if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) return null;
  const used = Math.max(0, Math.min(1, (now - from) / (to - from)));
  const left = Math.ceil((to - now) / 86400000);
  const total = Math.round((to - from) / 86400000);
  const tone = left < 0 ? 'bad' : left <= 30 ? 'warn' : 'good';
  const bar = svg('svg', { class: `lt-track lt-${tone}`, viewBox: '0 0 100 8', preserveAspectRatio: 'none', 'aria-hidden': 'true', focusable: 'false' },
    svg('rect', { x: 0, y: 0, width: 100, height: 8, class: 'lt-rest' }),
    svg('rect', { x: 0, y: 0, width: used * 100, height: 8, class: 'lt-used' }),
    svg('rect', { x: Math.min(99.4, used * 100), y: 0, width: 0.6, height: 8, class: 'lt-now' }));
  return h('span', { class: 'ltbar', role: 'img', 'aria-label': left < 0 ? `expired ${-left} days ago, of a ${total}-day lifetime` : `${left} days left of ${total}` }, bar);
}

/** The TLS hygiene score as a 180° gauge, with the band word under the number. */
export function gauge(score, band, tone) {
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const root = svg('svg', { class: `gauge gauge-${tone}`, viewBox: '0 0 200 110', role: 'img', 'aria-label': `${score} out of 100, ${band}` },
    svg('path', { d: 'M14 100 A86 86 0 0 1 186 100', class: 'gauge-track', pathLength: 100 }),
    svg('path', { d: 'M14 100 A86 86 0 0 1 186 100', class: 'gauge-fill', pathLength: 100, 'stroke-dasharray': `${pct * 100} 100` }));
  root.appendChild(svg('text', { x: 100, y: 84, 'text-anchor': 'middle', class: 'gauge-n' }, String(score)));
  root.appendChild(svg('text', { x: 100, y: 104, 'text-anchor': 'middle', class: 'gauge-band' }, band));
  return root;
}

/** Readiness L0 to L4, filled up to the level. */
export function levelStepper(level) {
  return h('span', { class: 'lstep', role: 'img', 'aria-label': level < 0 ? 'Level not determined' : `Level ${level} of 4` },
    [0, 1, 2, 3, 4].map((l) => h('span', { class: `lstep-seg${l <= level ? ' on' : ''}${l === level ? ' here' : ''}` }, h('span', { class: 'lstep-bar' }), h('span', { class: 'lstep-l' }, `L${l}`))));
}

/** A proportional bar of counts and its legend. segments: [{ n, label, tone }]. */
export function stackBar(segments, label) {
  const shown = segments.filter((s) => s.n > 0);
  const bar = h('span', { class: 'stackbar', role: 'img', 'aria-label': label || shown.map((s) => `${s.n} ${s.label}`).join(', ') });
  for (const s of shown) {
    const seg = h('span', { class: `stack-seg tone-fill-${s.tone}`, title: `${s.n} ${s.label}` });
    seg.style.flexGrow = String(s.n);
    bar.appendChild(seg);
  }
  const legend = h('span', { class: 'stack-legend' }, shown.map((s) => h('span', null, h('span', { class: `stack-dot tone-fill-${s.tone}`, 'aria-hidden': 'true' }), h('b', null, String(s.n)), ` ${s.label}`)));
  return { bar, legend };
}

/** The sticky row of section chips, each with its state's dot. items: [{ id, label, tone }]. */
export function jumpNav(items, onGo) {
  return h('nav', { class: 'jump', 'aria-label': 'On this page' }, items.map((it) => h('a', { href: `#${it.id}`, class: 'jump-chip', onclick: (e) => {
    e.preventDefault();
    if (onGo) onGo(it.id);
    else document.getElementById(it.id)?.scrollIntoView({ block: 'start' });
  } }, h('span', { class: `jump-dot tone-fill-${it.tone}`, 'aria-hidden': 'true' }), it.label)));
}
