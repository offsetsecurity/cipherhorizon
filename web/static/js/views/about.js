// About: version, the readiness scale, how the TLS hygiene score works, and the limits of what is measured.
import { h } from '../dom.js';
import { api } from '../api.js';
import { LEVELS, levelClass } from '../charts.js';
import { citations } from '../ui.js';

const MEANING = {
  '-1': 'The scan could not establish what the endpoint supports, so no level is given rather than a guess.',
  0: 'The endpoint does not offer TLS 1.3, so it cannot use a hybrid post-quantum key exchange at all.',
  1: 'TLS 1.3 is available but no post-quantum key exchange is offered. Recorded traffic is exposed to harvest-now-decrypt-later.',
  2: 'A hybrid post-quantum group is accepted, but a current client does not end up using it.',
  3: 'A current client negotiates a hybrid post-quantum key exchange with this endpoint. Traffic recorded today is protected against a future quantum computer.',
  4: 'Post-quantum key exchange and a post-quantum certificate signature. Rare today; requires ML-DSA certificates.',
};

const SOURCES = [
  ['FIPS 203 (ML-KEM)', 'https://csrc.nist.gov/pubs/fips/203/final'],
  ['FIPS 204 (ML-DSA)', 'https://csrc.nist.gov/pubs/fips/204/final'],
  ['NIST IR 8547 (draft): transition to post-quantum cryptography standards', 'https://csrc.nist.gov/pubs/ir/8547/ipd'],
  ['IANA TLS Supported Groups registry', 'https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8'],
  ['RFC 9325: recommendations for secure use of TLS', 'https://www.rfc-editor.org/rfc/rfc9325'],
];

export async function render(root) {
  const a = await api.about();
  root.appendChild(h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'About'), h('div', { class: 'sub' }, `${a.name} ${a.version}`))));

  root.appendChild(h('div', { class: 'callout' }, h('b', null, 'Use only on systems you are authorised to test. '), a.notice));

  root.appendChild(h('section', { class: 'card' }, h('h2', null, 'PQC readiness levels'),
    h('p', { class: 'muted' }, 'This scale is this product’s own. Each fact behind a level is separately sourced from a standard, and shown with its evidence.'),
    h('ul', { class: 'legend stack' }, LEVELS.slice().reverse().map(({ level, name, short }) =>
      h('li', null, h('span', { class: `badge lvbadge ${levelClass(level)}` }, h('b', null, short), ` ${name}`), ' ', MEANING[level])))));

  root.appendChild(h('section', { class: 'card' }, h('h2', null, 'How the TLS hygiene score works'),
    h('p', null, 'The score starts at 100 and takes points off for each finding on the endpoint: 40 for a critical one, 20 for high, 10 for medium, 4 for low. ',
      'Each distinct problem counts once. A critical finding limits the score to 29 and a high one to 74, so a serious problem cannot be averaged away.'),
    h('p', null, 'Bands: Strong (90 and above), Sound (75 to 89), Fair (55 to 74), Weak (30 to 54), Broken (below 30).'),
    h('p', null, 'Every point taken off is listed with the finding it came from, and every finding cites its sources. The weights are this product’s own choice; they are not a standard.'),
    h('p', { class: 'muted' }, 'Post-quantum findings are not counted. The readiness level answers that question separately, so a well-configured endpoint can score Strong and still be exposed to harvest-now-decrypt-later.')));

  root.appendChild(h('section', { class: 'card' }, h('h2', null, 'What is not measured'),
    h('ul', null, [
      'HTTP-layer headers such as HSTS, and certificate revocation status.',
      'Behavioural vulnerabilities (for example Heartbleed or ROBOT): the scanner sends no exploit traffic. Findings such as POODLE or Sweet32 are inferred from what the endpoint offers.',
      'Anything reachable only with client certificates, or only from another network.',
      'STARTTLS protocols: only direct TLS endpoints are scanned.',
    ].map((t) => h('li', null, t)))));

  root.appendChild(h('section', { class: 'card' }, h('h2', null, 'This installation'),
    h('dl', { class: 'kv' },
      h('dt', null, 'Version'), h('dd', null, a.version),
      h('dt', null, 'Evaluation rules'), h('dd', null, a.evalVersion),
      h('dt', null, 'IANA registries'), h('dd', null, `retrieved ${a.registryRetrieved}`),
      h('dt', null, 'History kept'), h('dd', null, `the last ${a.retentionPerAsset} scans of each endpoint`),
      h('dt', null, 'Concurrent scans'), h('dd', null, String(a.maxConcurrentScans)),
      h('dt', null, 'Loopback targets'), h('dd', null, a.allowLoopback ? 'allowed' : 'blocked'),
      h('dt', null, 'Access token'), h('dd', null, a.authRequired ? 'required' : 'not required (loopback only)'))));

  root.appendChild(h('section', { class: 'card' }, h('h2', null, 'Sources'), citations(SOURCES.map(([title, url]) => ({ title, url })))));
  return null;
}
