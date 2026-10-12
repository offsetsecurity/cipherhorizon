// About (UX-REVIEW-008 S4): what this product is, which version runs here, who makes it, and the
// licences and data it ships with. How to use it is in Help; how this server is set up, in Settings.
import { h, brandMark } from '../dom.js';
import { api } from '../api.js';

const STANDARDS = [
  ['NIST IR 8547', 'Transition to post-quantum cryptography: quantum-vulnerable algorithms deprecated after 2030, disallowed after 2035'],
  ['FIPS 203, 204, 205', 'ML-KEM, ML-DSA and SLH-DSA, the post-quantum algorithms'],
  ['RFC 8446, RFC 9325', 'TLS 1.3, and recommendations for using TLS securely'],
  ['CycloneDX 1.6, 1.7', 'The CBOM format of the inventory'],
];

const COMPONENTS = [
  ['Geist and Geist Mono', 'Vercel', 'SIL Open Font License 1.1'],
  ['Newsreader', 'Production Type', 'SIL Open Font License 1.1'],
  ['modernc.org/sqlite', 'the modernc authors', 'BSD-3-Clause'],
  ['CycloneDX Go library', 'OWASP CycloneDX', 'Apache-2.0'],
];

export async function render(root) {
  const [a, ref] = await Promise.all([api.about(), api.referenceData().catch(() => null)]);

  root.appendChild(h('section', { class: 'about-id' },
    h('span', { class: 'about-id-mark', 'aria-hidden': 'true' }, brandMark('color')),
    h('div', null,
      h('h1', null, a.name || 'CipherHorizon'),
      h('p', { class: 'about-id-line' }, 'TLS, SSH and post-quantum scanner, and cryptographic inventory'),
      h('p', { class: 'muted mono small' }, `Version ${a.version} · evaluation rules ${a.evalVersion}`))));

  root.appendChild(h('section', { class: 'card about-body' },
    h('p', null, 'CipherHorizon scans TLS endpoints and SSH servers and tells you how ready each one is for post-quantum cryptography, what is weak and what to fix first. ',
      'It can also inventory the cryptography on your machines and export everything as one CycloneDX CBOM. It runs on your own machine or network and makes no connection except the scans you start.'),
    h('div', { class: 'row' },
      h('a', { class: 'btn btn-secondary', href: '#/help' }, 'Help'),
      h('a', { class: 'btn btn-secondary', href: '#/settings' }, 'Settings'),
      h('a', { class: 'btn btn-secondary', href: '/api/v1/openapi.json' }, 'API description'))));

  root.appendChild(h('section', { class: 'card' }, h('h2', null, 'Standards'),
    h('dl', { class: 'kv' }, STANDARDS.flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)])),
    h('p', { class: 'hint' }, 'The readiness level and the hygiene score are this product’s own measures; how each is worked out is in Help.')));

  root.appendChild(h('section', { class: 'card' }, h('h2', null, 'Developed by'),
    h('p', null, h('a', { href: 'https://offsetsecurity.net/', target: '_blank', rel: 'noopener' }, 'Offset Security'),
      '. CipherHorizon is open source under the Apache License 2.0. For help planning a migration to post-quantum cryptography, see Offset’s ',
      h('a', { href: 'https://offsetsecurity.net/post-quantum-cryptography-readiness.html', target: '_blank', rel: 'noopener' }, 'post-quantum readiness practice'), '.')));

  root.appendChild(h('section', { class: 'card' }, h('h2', null, 'Open-source components'),
    h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
      h('thead', null, h('tr', null, ['Component', 'By', 'Licence'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, COMPONENTS.map(([n, by, l]) => h('tr', null, h('td', null, n), h('td', { class: 'muted' }, by), h('td', { class: 'muted' }, l))))))));

  if (ref) {
    root.appendChild(h('section', { class: 'card' }, h('h2', null, 'Reference data'),
      h('p', { class: 'text-2' }, 'Endpoints are judged against these dated lists, compiled into this version. Nothing is downloaded while it runs. A list older than ',
        `${ref.staleAfterDays} days is flagged.`),
      h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
        h('thead', null, h('tr', null, ['List', 'Entries', 'Retrieved', 'Licence'].map((c) => h('th', { scope: 'col' }, c)))),
        h('tbody', null, ref.lists.map((l) => h('tr', null,
          h('td', null, h('b', null, l.name), h('div', { class: 'hint' }, l.source)),
          h('td', { class: 'num' }, String(l.count)),
          h('td', null, l.retrieved, l.stale ? h('div', null, h('span', { class: 'badge b-warn' }, `${l.ageDays} days old`)) : null),
          h('td', { class: 'hint' }, l.licence)))))),
      h('p', { class: 'hint' }, ref.attribution)));
  }
  return null;
}
