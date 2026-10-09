// Help (UX-REVIEW-008 S4): how to use CipherHorizon and how it judges, in one place with a
// contents list. Reference material moved here from About; About now says only what the product is.
import { h } from '../dom.js';
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

const code = (s) => h('code', null, s);
const cmd = (s) => h('pre', { class: 'help-cmd' }, s);

const TOPICS = [
  ['scan', 'Scan an endpoint'],
  ['machines', 'Inventory a machine'],
  ['import', 'Import a CBOM'],
  ['levels', 'Post-quantum readiness levels'],
  ['score', 'The TLS hygiene score'],
  ['limits', 'What is and is not checked'],
  ['cli', 'Command line and CI'],
  ['sources', 'Sources'],
];

export async function render(root) {
  const a = await api.about().catch(() => ({}));
  root.appendChild(h('div', { class: 'page-head' },
    h('div', null, h('h1', null, 'Help'), h('div', { class: 'sub' }, 'How to use CipherHorizon, and how it reaches its verdicts.'))));

  const toc = h('nav', { class: 'help-toc', 'aria-label': 'Help topics' },
    h('ol', null, TOPICS.map(([id, title]) => h('li', null, h('a', { href: `#/help`, 'data-target': id, onclick: (e) => {
      e.preventDefault();
      document.getElementById(`help-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } }, title)))));
  const sec = (id, title, ...body) => h('section', { class: 'card help-sec', id: `help-${id}`, 'aria-labelledby': `help-${id}-h` },
    h('h2', { id: `help-${id}-h` }, title), ...body);

  const body = h('div', { class: 'help-body' },
    sec('scan', 'Scan an endpoint',
      h('p', null, 'Type an address on the Overview, or use ', h('b', null, 'Scan a URL'), ' on the Endpoints page, and press Enter. An address is a host name or IP with an optional port (443 by default); a pasted URL is reduced to its host and port.'),
      h('p', null, 'Mail, directory and database services that start in plain text are scanned through STARTTLS. It is chosen by port (25, 587, 143, 110, 21, 5222, 389 and 5432), by a scheme such as ', code('smtp://mail.example.com'),
        ', or when you add the endpoint (', h('i', null, 'How it starts TLS'), ').'),
      h('p', null, 'To add many at once, use ', h('b', null, 'Endpoints → Add endpoints → Paste a list'), '. Each endpoint can be rescanned on a schedule from its page.'),
      h('p', { class: 'callout' }, h('b', null, 'Scan only systems you own or are authorised to test. '), 'A scan makes a few hundred short TLS handshakes to its target and contacts nothing else.')),
    sec('machines', 'Inventory a machine',
      h('p', null, 'Two short scripts, PowerShell for Windows and shell for Linux, list a machine’s cryptographic software and certificates in a plain-text file you can read before uploading. They install nothing, change nothing, read no key material and make no network connection.'),
      h('div', { class: 'row' }, button('Step-by-step instructions', () => collectDialog(null), 'secondary')),
      inventoryScriptsBlock()),
    sec('import', 'Import a CBOM',
      h('p', null, 'A CycloneDX CBOM from another tool can be imported under ', h('b', null, 'Inventory → Add data'), '. You choose the system it belongs to. Imported facts are kept with their source and never overwrite what was observed.')),
    sec('levels', 'Post-quantum readiness levels',
      h('p', { class: 'text-2' }, 'The scale is this product’s own. Each fact behind a level comes from a standard and is shown with its evidence on the endpoint’s page.'),
      h('div', { class: 'readylist' }, LEVELS.slice().reverse().map(({ level, name, short }) =>
        h('div', { class: 'readylist-row' },
          h('span', { class: `badge lvbadge ${levelClass(level)}` }, h('b', null, short), ` ${name}`),
          h('p', null, MEANING[level]))))),
    sec('score', 'The TLS hygiene score',
      h('p', null, 'The score starts at 100 and takes off points for each finding on the endpoint: 40 for a critical one, 20 for high, 10 for medium, 4 for low. ',
        'Each distinct problem counts once. A critical finding limits the score to 29 and a high one to 74, so a serious problem cannot be averaged away.'),
      h('p', null, 'Bands: Strong (90 and above), Sound (75 to 89), Fair (55 to 74), Weak (30 to 54), Broken (below 30). Every point taken off is listed on the endpoint’s page with the finding it came from.'),
      h('p', { class: 'text-2' }, 'Post-quantum findings are not counted: the readiness level answers that separately, so an endpoint can score Strong and still be exposed to harvest-now-decrypt-later. The weights are this product’s own choice, not a standard.')),
    sec('limits', 'What is and is not checked',
      h('p', null, 'Every protocol from SSLv2 to TLS 1.3, every cipher suite and key-exchange group, the certificate chain against the bundled root stores, OCSP stapling, Certificate Transparency, and session features: 55 checks, each listed on the endpoint’s page as found, passed or not applicable.'),
      h('p', null, h('b', null, 'One HTTP request. '), 'Every check exchanges only TLS handshake messages except one: after the handshake, a plain ', code('GET /'),
        ' is sent to read the ', code('Strict-Transport-Security'), ' header (at most 8 KiB, no body kept, no redirect followed). This server has it ',
        h('b', null, a.httpChecks === false ? 'off' : 'on'), '; ', code('--http-checks=false'), ' turns it off.'),
      h('p', null, h('b', null, 'Not checked:')),
      h('ul', null, [
        'Live revocation: the CA’s OCSP responder and CRL are not contacted; a scan talks only to its target.',
        'Behavioural vulnerabilities such as Heartbleed or ROBOT: no exploit traffic is sent. Attacks such as POODLE or Sweet32 are inferred from the configuration and labelled as such.',
        'Anything reachable only with a client certificate, or only from another network.',
      ].map((t) => h('li', null, t))),
      h('p', null, 'Private certificate authorities: add your CA to a system (its page → CA bundle) or start the server with ', code('--ca-bundle FILE'), '; endpoints are then judged against it too.')),
    sec('cli', 'Command line and CI',
      h('p', null, 'The same scanner runs from the command line, with no server:'),
      cmd('cipherhorizon tls scan example.com\ncipherhorizon tls scan smtp://mail.example.com\ncipherhorizon tls scan --json example.com'),
      h('p', null, 'In a pipeline, ', code('--fail-on'), ' exits with code 3 when a target meets a condition, for example losing its post-quantum key exchange:'),
      cmd("cipherhorizon tls scan --fail-on 'level<L3,severity>=high' api.example.com"),
      h('p', { class: 'text-2' }, 'Conditions: ', code('level<L3'), ', ', code('score<70'), ', ', code('severity>=high'), ', ', code('finding=PROTO.TLS10'),
        '. Scripts can use this server’s API with an automation token; the API is described at ', h('a', { href: '/api/v1/openapi.json' }, '/api/v1/openapi.json'), '.')),
    sec('sources', 'Sources', citations(SOURCES.map(([title, url]) => ({ title, url })))));

  root.appendChild(h('div', { class: 'help-layout' }, toc, body));
  return null;
}
