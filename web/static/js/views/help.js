// Help (UX-REVIEW-008 S4): how to use CipherHorizon and how it judges, in one place with a
// contents list. Reference material moved here from About; About now says only what the product is.
import { h } from '../dom.js';
import { api } from '../api.js';
import { LEVELS, levelClass } from '../charts.js';
import { citations, button } from '../ui.js';
import { inventoryScriptsBlock, collectDialog } from '../guide.js';

const MEANING = {
  '-1': 'The scan could not establish what the endpoint supports, so no level is given rather than a guess.',
  0: 'The protocol in use cannot carry a post-quantum key exchange: a TLS endpoint without TLS 1.3, or an SSH server that speaks only SSH-1.',
  1: 'Only classical key exchange is offered (TLS 1.3 without a post-quantum group, or SSH without a hybrid method). Recorded traffic is exposed to harvest-now-decrypt-later.',
  2: 'A hybrid post-quantum key exchange is offered, but a current client does not end up using it.',
  3: 'A current client negotiates a hybrid post-quantum key exchange with this endpoint (for SSH, OpenSSH 10.6). Traffic recorded today is protected against a future quantum computer.',
  4: 'Post-quantum key exchange and post-quantum authentication: an ML-DSA certificate (presented, or held for clients that ask), or an ML-DSA SSH host key such as ssh-mldsa44-ed25519.',
};

const SOURCES = [
  ['FIPS 203 (ML-KEM)', 'https://csrc.nist.gov/pubs/fips/203/final'],
  ['FIPS 204 (ML-DSA)', 'https://csrc.nist.gov/pubs/fips/204/final'],
  ['NIST IR 8547 (draft): transition to post-quantum cryptography standards', 'https://csrc.nist.gov/pubs/ir/8547/ipd'],
  ['IANA TLS Supported Groups registry', 'https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8'],
  ['RFC 9325: recommendations for secure use of TLS', 'https://www.rfc-editor.org/rfc/rfc9325'],
  ['RFC 4253: the SSH transport layer protocol', 'https://www.rfc-editor.org/rfc/rfc4253'],
  ['RFC 9142: key exchange method updates and recommendations for SSH', 'https://www.rfc-editor.org/rfc/rfc9142'],
  ['RFC 10042: hybrid post-quantum key exchange with ML-KEM in SSH', 'https://www.rfc-editor.org/rfc/rfc10042'],
];
const KIND_WORDS = { kex: 'Key exchange', 'host-key': 'Host keys', cipher: 'Ciphers', mac: 'MACs', compression: 'Compression' };

const code = (s) => h('code', null, s);
const cmd = (s) => h('pre', { class: 'help-cmd' }, s);

const TOPICS = [
  ['protocols', 'Protocols, and how each is judged'],
  ['scan', 'Scan a TLS endpoint'],
  ['ssh', 'Scan an SSH server'],
  ['machines', 'Inventory a machine'],
  ['import', 'Import a CBOM'],
  ['levels', 'Post-quantum readiness levels'],
  ['score', 'The TLS hygiene score'],
  ['strength', 'Classical strength'],
  ['baseline', 'The SSH baseline'],
  ['limits', 'What is and is not checked'],
  ['charts', 'Charts and filtered lists'],
  ['server', 'Running the server'],
  ['cli', 'Command line and CI'],
  ['sources', 'Sources'],
];

export async function render(root) {
  const [a, bl] = await Promise.all([api.about().catch(() => ({})), api.sshBaselines().catch(() => null)]);
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
    sec('protocols', 'Protocols, and how each is judged',
      h('p', null, 'CipherHorizon scans the protocols that carry an organisation’s long-lived secrets: TLS today, SSH now, and IKE (VPN gateways) next. Each protocol has its own page in the menu, ',
        h('b', null, 'TLS endpoints'), ' and ', h('b', null, 'SSH servers'), ', and its own way of judging quality. One question is the same everywhere: is recorded traffic exposed to harvest-now-decrypt-later? That is the readiness level, L0 to L4.'),
      h('div', { class: 'tablewrap' }, h('table', { class: 'compact' },
        h('thead', null, h('tr', null, ['', 'TLS endpoints', 'SSH servers'].map((c) => h('th', { scope: 'col' }, c)))),
        h('tbody', null,
          h('tr', null, h('th', { scope: 'row' }, 'What a scan sends'), h('td', null, 'A few hundred short TLS handshakes, and one HTTP request for HSTS.'), h('td', null, 'A handful of key exchanges. Never a login.')),
          h('tr', null, h('th', { scope: 'row' }, 'Readiness'), h('td', null, 'L0 to L4, by TLS 1.3, its groups and the certificate.'), h('td', null, 'L0 to L4, by the key exchange and the host key.')),
          h('tr', null, h('th', { scope: 'row' }, 'Quality'), h('td', null, 'The TLS hygiene score, 0 to 100.'), h('td', null, 'Meets the SSH baseline, or the changes to make. No score.'))))),
      h('p', { class: 'text-2' }, 'No list, total or sort ever adds an SSH result to a TLS score: they answer different questions.')),
    sec('scan', 'Scan a TLS endpoint',
      h('p', null, 'Type an address on the Overview and press Enter, or use ', h('b', null, 'Add TLS endpoints'), ' on the TLS endpoints page, which also takes a name, tags and how the service starts TLS, and scans it straight away unless you untick ', h('i', null, 'Scan now'), '. An address is a host name or IP with an optional port (443 by default); a pasted URL is reduced to its host and port. The box shows ', h('i', null, 'Scan as TLS'), ' or ', h('i', null, 'Scan as SSH'), ' before it scans; click it to change.'),
      h('p', null, 'Mail, directory and database services that start in plain text are scanned through STARTTLS. It is chosen by port (25, 587, 143, 110, 21, 5222, 389 and 5432), by a scheme such as ', code('smtp://mail.example.com'),
        ', or when you add the endpoint (', h('i', null, 'How it starts TLS'), ').'),
      h('p', null, 'To add many at once, use ', h('b', null, 'TLS endpoints → Add TLS endpoints → Paste a list'), '. Each endpoint can be rescanned on a schedule from its page.'),
      h('p', { class: 'callout' }, h('b', null, 'Scan only systems you own or are authorised to test. '), 'A scan makes a few hundred short TLS handshakes to its target and contacts nothing else.')),
    sec('ssh', 'Scan an SSH server',
      h('p', null, 'Type ', code('ssh://bastion.example.com'), ' or an address on port 22, or use ', h('b', null, 'SSH servers → Add SSH servers'), '. The report shows readiness, whether the server meets the SSH baseline (and the ', code('sshd_config'), ' lines that would make it), every check, the CBOM and history.'),
      h('p', null, h('b', null, 'What is sent. '), 'One connection reads the server’s identification and its algorithm lists. One more negotiates as OpenSSH 10.6 would and, when it can, runs the key exchange to the server’s reply and checks its signature. Then one key exchange per host key type fetches each key. Every connection ends before any key is used: no login, no channel, never a password.'),
      h('p', null, h('b', null, 'Readiness. '), 'L1 when no post-quantum hybrid key exchange is offered; L3 when OpenSSH 10.6’s client gets one (', code('mlkem768x25519-sha256'), ', or ', code('sntrup761x25519-sha512'),
        ', which is noted as not a NIST standard); L4 with a post-quantum host key; L0 for an SSH-1-only server.'),
      h('p', null, h('b', null, 'Fixing what it finds. '), 'The Configuration tab gives the ', code('sshd_config'), ' lines to copy: ', code('KexAlgorithms'), ', ', code('HostKeyAlgorithms'), ', ', code('Ciphers'), ', ', code('MACs'),
        ' and ', code('Compression'), '. Put them at the top of ', code('/etc/ssh/sshd_config'), ' (sshd uses the first value of each keyword), check with ', code('sshd -t'), ', reload sshd and scan again. OpenSSH 9.9 added ML-KEM key exchange and 10.0 made it the default.'),
      h('p', { class: 'text-2' }, 'Not checked: authentication (no login is attempted), the server software’s own vulnerabilities (its version is shown, not judged), and the size of group-exchange Diffie-Hellman groups.')),
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
      h('p', null, 'A TLS endpoint’s score starts at 100 and takes off points for each finding on it: 40 for a critical one, 20 for high, 10 for medium, 4 for low. ',
        'Each distinct problem counts once. A critical finding limits the score to 29 and a high one to 74, so a serious problem cannot be averaged away.'),
      h('p', null, 'Bands: Strong (90 and above), Sound (75 to 89), Fair (55 to 74), Weak (30 to 54), Broken (below 30). Every point taken off is listed on the endpoint’s page with the finding it came from.'),
      h('p', { class: 'text-2' }, 'Post-quantum findings are not counted: the readiness level answers that separately, so an endpoint can score Strong and still be exposed to harvest-now-decrypt-later. The weights are this product’s own choice, not a standard. SSH servers have no score: see the SSH baseline.')),
    sec('strength', 'Classical strength',
      h('p', null, 'Every algorithm, key and cipher suite shows how strong it is against today’s computers, in bits: about 2 to that power operations would break it. The numbers are NIST’s, computed the way NIST computes them: RSA and Diffie-Hellman by the General Number Field Sieve estimate (2048 bits gives 112, 3072 gives 128), elliptic curves at half their order (P-256 and X25519 give 128), AES by its key, hashes by their collision resistance.'),
      h('p', null, h('b', null, 'A cipher suite is as strong as its weakest part'), ': the cipher, the key exchange, the certificate key and the MAC. It is '),
      h('ul', null, [
        [h('b', null, 'Insecure'), ' when a part is broken (no encryption, export, RC4, single DES, no authentication) or under 80 bits;'],
        [h('b', null, 'Weak'), ' from 80 to 111 bits, or with a 64-bit block cipher such as 3DES, or without forward secrecy;'],
        [h('b', null, 'Acceptable'), ' at 112 bits or more, but under 128 or not an AEAD cipher;'],
        [h('b', null, 'Strong'), ' at 128 bits or more in every part, with an AEAD cipher and forward secrecy.'],
      ].map((x) => h('li', null, x))),
      h('p', { class: 'text-2' }, 'An RSA-2048 certificate is 112 bits, so the suites it authenticates read Acceptable. Each suite names its weakest part. The words are this product’s own; the numbers and their sources are in the methodology. Post-quantum readiness is separate: a 128-bit classical algorithm can still be broken by a quantum computer.')),
    sec('baseline', 'The SSH baseline',
      h('p', null, 'An SSH server is judged against a baseline: a named, versioned list of what an SSH server may offer and must offer, every entry cited. It ', h('b', null, 'meets'),
        ' the baseline when nothing it offers should be off and every requirement holds; otherwise the report lists the changes and the ', code('sshd_config'), ' lines that make them. A server whose lists could not be read is not judged.'),
      ...(bl && bl.baselines ? bl.baselines.map((b) => h('div', { class: 'help-baseline' },
        h('h3', null, b.title, b.id === bl.default ? ' (default)' : '', h('span', { class: 'muted small' }, ` · ${b.id}, version ${b.version}`)),
        h('p', null, h('b', null, 'Requires: '), b.requires.map((r) => r.text).join('; '), '.'),
        h('dl', { class: 'kv' }, Object.keys(KIND_WORDS).filter((k) => b.allowed[k]).flatMap((k) => [
          h('dt', null, KIND_WORDS[k]),
          h('dd', null, b.allowed[k].map((e, i) => [i ? ', ' : '', code(e.name)]))])))) : []),
      h('p', { class: 'text-2' }, 'Every entry’s source and the OpenSSH version that first offers it: ', code('cipherhorizon ssh baselines'), '. The baseline is this product’s own; BSI TR-02102-4 is planned as a second one.')),
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
    sec('charts', 'Charts and filtered lists',
      h('p', null, 'Every figure that counts something opens it. On the Overview, a readiness level opens the endpoints at that level, a severity opens those findings, and an exposed count opens the exposed endpoints. On Inventory, a ring segment, a bar or a row opens the algorithms, protocol versions, software or certificates it counts. On a report, a point in ',
        h('i', null, 'Readiness over time'), ' opens the scan it stands for.'),
      h('p', null, 'Hover or Tab to a mark to see what it counts; Enter opens it. The list that opens is filtered, and says so: a filter the page has no control for shows as a chip above the list, with × to remove it.'),
      h('p', { class: 'text-2' }, 'The filters are part of the address (for example ', code('#/inventory/certificates?expires=30'), '), so a filtered list can be bookmarked or shared, and Back returns to the chart.')),
    sec('server', 'Running the server',
      h('p', null, 'The server listens on ', code('127.0.0.1:8080'), ' unless told otherwise. Another port:'),
      cmd('cipherhorizon serve --port 9000\ncipherhorizon serve --addr 0.0.0.0 --port 9443 --tls-cert cert.pem --tls-key key.pem --sign-in on'),
      h('p', null, 'Where editing the command is awkward (a container, a service), set ', code('CIPHERHORIZON_PORT'), ' (and ', code('CIPHERHORIZON_ADDR'), ' for the interface); a flag wins over the variable, and ', code('cipherhorizon healthcheck'), ' follows the same variable. ',
        code('--port 0'), ' takes any free port and prints it. If the port is taken, the server says so and suggests the next one.'),
      h('p', { class: 'text-2' }, 'Beyond this machine, the server needs HTTPS (or a TLS-terminating proxy and ', code('--plain-http'), ') and sign-in (or ', code('--open-network'), ').')),
    sec('cli', 'Command line and CI',
      h('p', null, 'The same scanner runs from the command line, with no server:'),
      cmd('cipherhorizon tls scan example.com\ncipherhorizon tls scan smtp://mail.example.com\ncipherhorizon ssh scan bastion.example.com\ncipherhorizon ssh baselines\ncipherhorizon tls scan --json example.com'),
      h('p', null, 'In a pipeline, ', code('--fail-on'), ' exits with code 3 when a target meets a condition, for example losing its post-quantum key exchange:'),
      cmd("cipherhorizon tls scan --fail-on 'level<L3,severity>=high' api.example.com\ncipherhorizon ssh scan --fail-on baseline bastion.example.com"),
      h('p', { class: 'text-2' }, 'Conditions: ', code('level<L3'), ', ', code('score<70'), ' (TLS), ', code('baseline'), ' (SSH), ', code('severity>=high'), ', ', code('finding=PROTO.TLS10'),
        '. Scripts can use this server’s API with an automation token; the API is described at ', h('a', { href: '/api/v1/openapi.json' }, '/api/v1/openapi.json'), '.')),
    sec('sources', 'Sources', citations(SOURCES.map(([title, url]) => ({ title, url })))));

  root.appendChild(h('div', { class: 'help-layout' }, toc, body));
  // #/help?topic=strength opens at that topic (links from the report's legends).
  const topic = new URLSearchParams(location.hash.split('?')[1] || '').get('topic');
  if (topic && TOPICS.some(([id]) => id === topic)) setTimeout(() => document.getElementById(`help-${topic}`)?.scrollIntoView({ block: 'start' }), 0);
  return null;
}
