// About: what this product is, how to inventory a machine, the readiness scale, how the TLS hygiene
// score works, and the limits of what is measured.
import { h, brandMark } from '../dom.js';
import { api } from '../api.js';
import { LEVELS, levelClass } from '../charts.js';
import { citations, button } from '../ui.js';
import { inventoryScriptsBlock, collectDialog } from '../guide.js';

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
  const [a, ref, bundle] = await Promise.all([api.about(), api.referenceData().catch(() => null), api.serverTrustAnchors().catch(() => null)]);
  root.appendChild(h('section', { class: 'about-hero' },
    h('div', { class: 'about-hero-mark', 'aria-hidden': 'true' },
      brandMark('Hero', 'rgba(17,17,30,.14)')),
    h('div', null,
      h('h1', null, a.name || 'CipherHorizon'),
      h('p', { class: 'about-hero-sub' }, 'Scans your TLS endpoints and collects your CBOMs into one cryptographic inventory, and tells you what is not ready for post-quantum.'),
      h('p', { class: 'muted mono small' }, `Version ${a.version}`))));

  root.appendChild(h('div', { class: 'callout' }, h('b', null, 'Use only on systems you are authorised to test. '), a.notice));

  root.appendChild(h('section', { class: 'card' },
    h('div', { class: 'row spread' },
      h('div', null, h('h2', null, 'Inventory a machine'),
        h('p', { class: 'text-2' }, 'Two short scripts, PowerShell for Windows and shell for Linux, list a machine’s cryptographic software and certificates in a plain-text file you can read before uploading. They read no key material and make no network connection. (The Go collector still exists for those who build it from source.)')),
      button('Full instructions', () => collectDialog(null))),
    inventoryScriptsBlock()));

  root.appendChild(h('section', { class: 'card' }, h('h2', null, 'PQC readiness levels'),
    h('p', { class: 'muted' }, 'This scale is this product’s own. Each fact behind a level is separately sourced from a standard, and shown with its evidence.'),
    h('div', { class: 'readylist' }, LEVELS.slice().reverse().map(({ level, name, short }) =>
      h('div', { class: 'readylist-row' },
        h('span', { class: `badge lvbadge ${levelClass(level)}` }, h('b', null, short), ` ${name}`),
        h('p', null, MEANING[level]))))));

  root.appendChild(h('section', { class: 'card' }, h('h2', null, 'How the TLS hygiene score works'),
    h('p', null, 'The score starts at 100 and takes points off for each finding on the endpoint: 40 for a critical one, 20 for high, 10 for medium, 4 for low. ',
      'Each distinct problem counts once. A critical finding limits the score to 29 and a high one to 74, so a serious problem cannot be averaged away.'),
    h('p', null, 'Bands: Strong (90 and above), Sound (75 to 89), Fair (55 to 74), Weak (30 to 54), Broken (below 30).'),
    h('p', null, 'Every point taken off is listed with the finding it came from, and every finding cites its sources. The weights are this product’s own choice; they are not a standard.'),
    h('p', { class: 'muted' }, 'Post-quantum findings are not counted. The readiness level answers that question separately, so a well-configured endpoint can score Strong and still be exposed to harvest-now-decrypt-later.')));

  root.appendChild(h('section', { class: 'card' }, h('h2', null, 'What is not measured'),
    h('ul', null, [
      'Live revocation status: the stapled OCSP response is read, but the CA’s OCSP responder and CRL are not contacted (the scan talks only to the endpoint).',
      'Behavioural vulnerabilities (for example Heartbleed or ROBOT): the scanner sends no exploit traffic. Findings such as POODLE or Sweet32 are inferred from what the endpoint offers.',
      'Anything reachable only with client certificates, or only from another network.',
      'STARTTLS protocols: only direct TLS endpoints are scanned.',
    ].map((t) => h('li', null, t)))));

  root.appendChild(h('section', { class: 'card' }, h('h2', null, 'HTTP-layer check (HSTS)'),
    h('p', null, 'Every other check in this tool exchanges only TLS handshake messages: no application data is sent. This one is the exception: ',
      h('b', null, 'it sends one real HTTP request'), ' (a plain ', h('code', null, 'GET /'), ') to each scanned target after the handshake, and reads only the ',
      h('code', null, 'Strict-Transport-Security'), ' response header (at most 8 KiB, no body kept, no redirect followed).'),
    h('p', null, 'It is on by default. This installation has it ', a.httpChecks ? h('b', null, 'enabled') : h('b', null, 'disabled'), ' for every scan (server-wide ',
      h('code', null, '--http-checks=false'), ' turns it off). The CLI’s ', h('code', null, 'tls scan'), ' has the same flag, also on by default.')));

  if (ref) {
    root.appendChild(h('section', { class: 'card' }, h('h2', null, 'Reference data'),
      h('p', { class: 'text-2' }, 'Endpoints are judged against these dated lists, compiled into this version. Nothing is downloaded while it runs. A list older than ',
        `${ref.staleAfterDays} days is flagged here.`),
      h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
        h('thead', null, h('tr', null, ['List', 'Entries', 'Retrieved', 'Licence'].map((c) => h('th', { scope: 'col' }, c)))),
        h('tbody', null, ref.lists.map((l) => h('tr', null,
          h('td', null, h('b', null, l.name), h('div', { class: 'hint' }, l.source)),
          h('td', { class: 'num' }, String(l.count)),
          h('td', null, l.retrieved, l.stale ? h('div', null, h('span', { class: 'badge b-warn' }, `${l.ageDays} days old`)) : null),
          h('td', { class: 'hint' }, l.licence)))))),
      h('p', { class: 'hint' }, ref.attribution)));
  }
  if (bundle) {
    root.appendChild(h('section', { class: 'card' }, h('h2', null, 'Server-wide CA bundle'),
      bundle.anchors.length
        ? h('ul', { class: 'anchors-list' }, bundle.anchors.map((x) => h('li', null, h('div', null, h('b', null, x.subject),
          h('div', { class: 'fp' }, x.fingerprint)))))
        : h('p', { class: 'hint' }, 'None. Start the server with ', h('code', null, '--ca-bundle FILE'), ' to judge every endpoint against your private CAs as well; per-system bundles are set on each system’s page.')));
  }

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
