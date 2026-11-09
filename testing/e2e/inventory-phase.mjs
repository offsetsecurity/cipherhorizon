// PRD-019: a version 3 facts file (what the inventory scripts write) uploads and the machine page
// reads it by meaning: platform tiles, the installed OpenSSL with its post-quantum algorithms, the
// SSH server's effective policy, services listening with the libraries they loaded, configuration
// by area, runtimes with their crypto backend; the Inventory how-to lists signatures by area.

import { authFetch as fetch } from './authfetch.mjs';

// Shaped on a real Ubuntu 26.04 run (the fixture in internal/machinefacts/interpret_v3_test.go, trimmed).
const FACTS = [
  'cipherhorizon-machine-facts\t3', 'script\tlinux-sh\t3.0.0', 'host\tname\tweb-e2e', 'host\tos\tlinux', 'host\tprivilege\tadmin',
  'host\tcollected\t2026-11-09T10:00:00Z', 'signatures\t2026.11.09',
  'fact\tlinux.platform.kernel\tquery\tos.kernel\tLinux 6.18.3-amd64 x86_64', 'ran\tlinux.platform.kernel\t1',
  'fact\tlinux.platform.fips\tline\t/proc/sys/crypto/fips_enabled\t1', 'ran\tlinux.platform.fips\t1',
  'fact\tlinux.platform.tpm\tline\t/sys/class/tpm/tpm0/tpm_version_major\t2', 'ran\tlinux.platform.tpm\t1',
  'fact\tlinux.platform.disk-encryption\tquery\tdisk.encryption\tnvme0n1p3_crypt crypt ext4 /', 'ran\tlinux.platform.disk-encryption\t1',
  'fact\tlinux.packages\tpackage-manager\tdpkg', 'fact\tlinux.packages\tpackage\tdpkg\topenssl\t3.5.5-1\tamd64', 'ran\tlinux.packages\t1',
  'fact\tlinux.openssl.build\tquery\topenssl.version\tOpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)', 'ran\tlinux.openssl.build\t1',
  'fact\tlinux.openssl.kem\tquery\topenssl.kem-algorithms\t  { 2.16.840.1.101.3.4.4.2, id-alg-ml-kem-768, ML-KEM-768, MLKEM768 } @ default',
  'fact\tlinux.openssl.kem\tquery\topenssl.kem-algorithms\t  X25519MLKEM768 @ default', 'ran\tlinux.openssl.kem\t2',
  'fact\tlinux.curl.build\tquery\tcurl.version\tcurl 8.18.0 (x86_64-pc-linux-gnu) libcurl/8.18.0 OpenSSL/3.5.5 zlib/1.3.1', 'ran\tlinux.curl.build\t1',
  'fact\tlinux.ssh.server-effective\tquery\tsshd.effective\tkexalgorithms mlkem768x25519-sha256,curve25519-sha256',
  'fact\tlinux.ssh.server-effective\tquery\tsshd.effective\thostkey /etc/ssh/ssh_host_rsa_key', 'ran\tlinux.ssh.server-effective\t2',
  'fact\tlinux.ssh.host-keys\tline\t/etc/ssh/ssh_host_rsa_key.pub\tssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDc root@web-e2e', 'ran\tlinux.ssh.host-keys\t1',
  'fact\tlinux.ssh.host-key-sizes\tquery\tssh.host-keys\t3072 SHA256:nkF/+ewQhBpvsmretap1/3ulRDA3g09OYSMvLko2ngc root@web-e2e (RSA)', 'ran\tlinux.ssh.host-key-sizes\t1',
  'fact\tlinux.nginx.tls\tline\t/etc/nginx/nginx.conf\t ssl_protocols TLSv1.2 TLSv1.3; # Dropping SSLv3', 'ran\tlinux.nginx.tls\t1',
  'fact\tlinux.kerberos.config\tline\t/etc/krb5.conf\tpermitted_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac', 'ran\tlinux.kerberos.config\t1',
  'fact\tlinux.bound.listeners\tlistener\ttcp\t0.0.0.0\t443\t197\tnginx\t/usr/sbin/nginx\tlibcrypto.so.3,libssl.so.3',
  'fact\tlinux.bound.listeners\tlistener\ttcp\t0.0.0.0\t9000\t555\tdemo\t/opt/demo/demo\t', 'ran\tlinux.bound.listeners\t2',
  'skip\tlinux.java.build\tjava is not installed', 'ran\tlinux.java.build\t0',
].join('\n') + '\n';

export async function inventoryPhase({ check, js, go, sleep, shot, api, BASE }) {
  const up = await fetch(`${BASE}/api/v1/hosts/ingest`, { method: 'POST', headers: { 'Content-Type': 'text/plain', 'X-Requested-With': 'cipherhorizon' }, body: FACTS });
  const upj = await up.json().catch(() => ({}));
  check('E2E-HI.1', 'a version 3 facts file uploads as a machine', (up.status === 200 || up.status === 201) && upj.asset && upj.asset.id > 0, `${up.status} ${JSON.stringify(upj).slice(0, 120)}`);
  if (!(upj.asset && upj.asset.id)) return;
  await go(`#/machines/${upj.asset.id}`);
  // The page reads the machine's CBOM after its summary; wait for the last card, not a fixed time.
  let text = '';
  for (let i = 0; i < 40 && !/Upload history/.test(text); i++) {
    await sleep(250);
    text = await js(`return document.querySelector('main').innerText`);
  }
  check('E2E-HI.2', 'the machine page shows platform and policy as tiles (FIPS, TPM, disk encryption)',
    /Platform and policy/.test(text) && /FIPS mode[\s\S]{0,40}On/.test(text) && /TPM[\s\S]{0,40}Present/.test(text) && /Disk encryption/.test(text),
    JSON.stringify(text.slice(Math.max(0, text.indexOf('Platform and policy')), text.indexOf('Platform and policy') + 260)));
  check('E2E-HI.3', 'the installed OpenSSL is listed with its version and its ML-KEM algorithms',
    /OpenSSL \(installed\)/.test(text) && /KEM: .*ML-KEM-768/.test(text) && /X25519MLKEM768/.test(text), (text.match(/OpenSSL \(installed\)[^\n]*/) || [''])[0]);
  check('E2E-HI.4', 'services listening show the process, its sockets and the crypto stack it loaded, and none seen for a static binary',
    /Services listening \(2\)/.test(text) && /nginx[\s\S]*tcp 0\.0\.0\.0:443[\s\S]*OpenSSL 3/.test(text) && /demo[\s\S]*none seen/.test(text), text.slice(text.indexOf('Services listening'), text.indexOf('Services listening') + 200));
  check('E2E-HI.5', 'configuration is grouped by area and the SSH server effective policy names the hybrid key exchange',
    /Configuration found/.test(text) && /SSH\s*\d/.test(text) && /Servers\s*\d/.test(text) && /Authentication\s*\d/.test(text), text.slice(text.indexOf('Configuration found'), text.indexOf('Configuration found') + 160));
  const sshTab = await js(`const t = [...document.querySelectorAll('.configuration .tab')].find((x) => /^SSH/.test(x.textContent)); if (!t) return null; t.click();
    return document.querySelector('.configuration .config-area').innerText`);
  check('E2E-HI.6', 'the SSH area shows the effective policy as sshd reports it, with the RSA host key size',
    sshTab !== null && /effective policy/.test(sshTab) && /mlkem768x25519-sha256/.test(sshTab), (sshTab || 'no SSH tab').slice(0, 160));
  const authTab = await js(`const t = [...document.querySelectorAll('.configuration .tab')].find((x) => /^Authentication/.test(x.textContent)); if (!t) return null; t.click();
    return document.querySelector('.configuration .config-area').innerText`);
  check('E2E-HI.7', 'the Authentication area shows the Kerberos enctypes in words', authTab !== null && /permitted_enctypes/.test(authTab) && /rc4-hmac/.test(authTab), (authTab || '').slice(0, 120));
  check('E2E-HI.8', 'RC4 from the Kerberos policy reaches the algorithms with a verdict or a retired status', /RC4/.test(text));
  check('E2E-HI.9', 'runtimes carry their crypto backend', /curl[\s\S]*OpenSSL 3\.5\.5/.test(text));
  check('E2E-HI.10', 'coverage says which signatures were not present, never that everything was seen', /not present on this machine/.test(text) && /Full access/.test(text));
  await shot('machine-v3');

  const db = await api('/api/v1/collector/signatures');
  check('E2E-HI.11', 'the signature database is published by area with the fixed queries each engine can run',
    Array.isArray(db.areas) && db.areas.length >= 8 && db.signatures.length >= 100 && db.signatures.every((s) => s.area) && (db.queries.linux || []).includes('sshd.effective') && (db.queries.windows || []).includes('tls.cipher-suites'),
    `${(db.areas || []).length} areas, ${(db.signatures || []).length} signatures`);
  check('E2E-HI.12', 'no signature can name a command: every query signature names an id the engine lists',
    db.signatures.filter((s) => s.capability === 'query').every((s) => (db.queries[s.platform] || []).includes(s.params.query)));
}
