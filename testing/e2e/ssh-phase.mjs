// PRD-008 WP-B..G (SSH servers, a page per protocol, the SSH baseline; UX-DESIGN-007), driven
// through the browser on demo-targets: SSH servers from base+20 (9460 hybrid with OpenSSH-style
// MACs, 9461 classical, 9462 legacy, 9463 ML-DSA host key, 9465 SSH-1, 9467 hardened to meet the
// baseline). The ML-DSA TLS servers (9458, 9459) belong to pqs-phase.mjs.

export async function sshPhase({ check, js, go, sleep, shot, viewport, clickText }) {
  const waitDone = async (id) => {
    for (let i = 0; i < 160; i++) {
      const a = await js(`return (await fetch('/api/v1/assets/${id}')).json()`);
      if (a.lastDone || (a.latest && a.latest.status === 'failed')) return a;
      await sleep(500);
    }
    return null;
  };
  const scan = (id) => js(`await fetch('/api/v1/assets/${id}/scan', { method: 'POST', headers: { 'X-Requested-With': 'cipherhorizon' } })`);
  const text = () => js(`return document.querySelector('main').innerText`);
  const PORTS = [9460, 9461, 9462, 9463, 9465, 9467];
  await viewport(1440, 900, false);

  // E2E-H.1: SSH servers is a page of its own; its add dialog is preset to SSH; ssh:// in a pasted list.
  await go('#/ssh');
  await sleep(800);
  await js(`document.getElementById('ssh-add').click()`);
  await sleep(400);
  const preset = await js(`return document.getElementById('add-protocol').value`);
  await js(`document.getElementById('add-target').value = '127.0.0.1:9460'; document.getElementById('add-name').value = 'bastion-hybrid';
    document.querySelector('.modal form').requestSubmit();`);
  await sleep(1000);
  await js(`return fetch('/api/v1/assets/bulk', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'cipherhorizon' },
    body: JSON.stringify({ text: ['ssh://127.0.0.1:9461', 'ssh://127.0.0.1:9462', 'ssh://127.0.0.1:9463', 'ssh://127.0.0.1:9465', 'ssh://127.0.0.1:9467'].join(String.fromCharCode(10)) }) }).then((r) => r.json())`);
  const all = await js(`return (await fetch('/api/v1/assets?kind=endpoint')).json()`);
  const by = Object.fromEntries(all.filter((a) => PORTS.includes(a.port)).map((a) => [a.port, a]));
  check('E2E-H.1', 'SSH servers has its own page; its add dialog is preset to SSH; ssh:// in a list adds SSH servers',
    preset === 'ssh' && by[9460]?.protocol === 'ssh' && by[9460]?.name === 'bastion-hybrid' && PORTS.every((p) => by[p]?.protocol === 'ssh'),
    JSON.stringify({ preset, added: Object.values(by).map((a) => `${a.port}:${a.protocol}`) }));
  for (const p of PORTS) await scan(by[p].id);
  const done = {};
  for (const p of PORTS) done[p] = await waitDone(by[p].id);
  const d = (p) => done[p]?.lastDone || {};
  check('E2E-H.1b', 'levels: hybrid L3, classical L1, ML-DSA host key L4, SSH-1 L0; baseline: the hardened server meets it, the hybrid one needs 2 changes, the legacy one many; no SSH score',
    d(9460).readinessLevel === 3 && d(9461).readinessLevel === 1 && d(9463).readinessLevel === 4 && d(9465).readinessLevel === 0 &&
    d(9467).baselineMeets === true && d(9460).baselineMeets === false && d(9460).baselineChanges === 2 && d(9462).baselineChanges >= 5 &&
    PORTS.every((p) => !d(p).band && d(p).score === -1),
    JSON.stringify(PORTS.map((p) => [p, d(p).readinessLevel, d(p).baselineMeets, d(p).baselineChanges, d(p).band, d(p).score])));

  // E2E-H.1c: each list holds only its protocol, with its own columns.
  await go('#/');
  await sleep(400);
  await go('#/ssh');
  await sleep(1000);
  const ssh = await js(`return { rows: [...document.querySelectorAll('main tbody tr')].map((r) => r.innerText), head: document.querySelector('main thead').innerText, h1: document.querySelector('main h1').innerText }`);
  await shot('ssh-servers');
  await go('#/endpoints');
  await sleep(1000);
  const tls = await js(`return { rows: [...document.querySelectorAll('main tbody tr')].map((r) => r.innerText), head: document.querySelector('main thead')?.innerText || '', nav: [...document.querySelectorAll('#nav a')].map((a) => a.querySelector('span')?.innerText || '') }`);
  check('E2E-H.1c', 'SSH servers lists only SSH (Server, Baseline, Host key; no hygiene); TLS endpoints lists no SSH (TLS hygiene, Certificate expiry); the menu names both',
    ssh.h1 === 'SSH servers' && ssh.rows.length === PORTS.length && /Server/.test(ssh.head) && /Baseline/.test(ssh.head) && /Host key/.test(ssh.head) && !/hygiene/i.test(ssh.head) &&
    ssh.rows.some((r) => /✓ Meets/.test(r)) && ssh.rows.some((r) => /2 changes/.test(r)) && ssh.rows.some((r) => /Ed25519/.test(r)) &&
    !tls.rows.some((r) => /OpenSSH|:946[0-7]\b/.test(r)) && /TLS hygiene/.test(tls.head) && /Certificate expiry/.test(tls.head) &&
    tls.nav.includes('TLS endpoints') && tls.nav.includes('SSH servers'),
    JSON.stringify({ sshHead: ssh.head, n: ssh.rows.length, tlsHead: tls.head, nav: tls.nav }));

  // E2E-H.1d: an old #/endpoints/{id} link to an SSH server lands on its page under SSH servers.
  await go(`#/endpoints/${by[9460].id}`);
  await sleep(1400);
  const moved = await js(`return { hash: location.hash, crumb: document.querySelector('.crumbs')?.innerText || '' }`);
  check('E2E-H.1d', 'an old Endpoints link to an SSH server is redirected to #/ssh/{id}, under SSH servers',
    moved.hash === `#/ssh/${by[9460].id}` && /SSH servers/.test(moved.crumb), JSON.stringify(moved));

  // E2E-H.1e: the Overview scan box says what it will scan, and a click switches it. Nothing is submitted.
  await go('#/');
  await sleep(900);
  const chip = await js(`const i = document.getElementById('scan-target'); const c = document.querySelector('.scan-chip');
    const say = () => (c.hidden ? '' : c.innerText.split(String.fromCharCode(10))[0]);
    const type = (v) => { i.value = v; i.dispatchEvent(new Event('input')); return say(); };
    const out = { empty: type(''), port22: type('bastion.example.com:22') };
    c.click(); out.switched = say(); out.label = c.getAttribute('aria-label');
    out.https = type(''); out.https = type('https://example.com'); out.ssh = type('ssh://bastion.example.com'); type('');
    return out;`);
  check('E2E-H.1e', 'the scan box shows Scan as SSH for host:22, switches to TLS on a click, and follows the scheme',
    chip.empty === '' && chip.port22 === 'Scan as SSH' && chip.switched === 'Scan as TLS' && /change to SSH/.test(chip.label) && chip.https === 'Scan as TLS' && chip.ssh === 'Scan as SSH',
    JSON.stringify(chip));

  // E2E-H.2: every tab of an SSH report, in SSH's words, with the baseline and no score.
  const tabs = {};
  for (const t of ['summary', 'configuration', 'weaknesses', 'cbom', 'history']) {
    await go(`#/ssh/${by[9460].id}?tab=${t}`);
    await sleep(t === 'cbom' ? 1800 : 1000);
    tabs[t] = await text();
    if (t !== 'history') await shot(`ssh-report-${t}`);
  }
  const noTLS = Object.values(tabs).every((x) => !/TLS hygiene|cipher suite|certificate chain/i.test(x));
  const noScore = Object.values(tabs).every((x) => !/hygiene|out of 100/i.test(x));
  check('E2E-H.2', 'an SSH report: the Baseline tile and action, the sshd_config lines and requirements, per-algorithm baseline verdicts, every check, an ssh CBOM; no score and no TLS words',
    /Baseline/.test(tabs.summary) && /2 changes/.test(tabs.summary) && /Meet CipherHorizon SSH baseline 2026/.test(tabs.summary) && /\d+ things? to fix/.test(tabs.summary) &&
    /Make this server meet the baseline/.test(tabs.configuration) && /MACs hmac-sha2-256-etm@openssh\.com/.test(tabs.configuration) &&
    /What the baseline requires/.test(tabs.configuration) && /Should be off/.test(tabs.configuration) && /Allowed\s*· post-quantum/.test(tabs.configuration) &&
    /used by OpenSSH 10\.6/.test(tabs.configuration) && /checks run/.test(tabs.weaknesses) && /SSH-2\.0/.test(tabs.cbom) && noTLS && noScore,
    JSON.stringify({ summary: tabs.summary.slice(0, 220), noTLS, noScore }));

  await go(`#/ssh/${by[9467].id}?tab=configuration`);
  await sleep(1200);
  const hard = await text();
  await go(`#/ssh/${by[9467].id}`);
  await sleep(1000);
  const hardSum = await text();
  check('E2E-H.2c', 'the hardened server meets the baseline: the tile says Meets, every requirement is met, no lines to copy',
    /✓ Meets/.test(hardSum) && /Meets the baseline/.test(hard) && !/Make this server meet the baseline/.test(hard) && !/Not met/.test(hard),
    hard.slice(0, 200));

  // E2E-H.2b: phone width, no sideways scroll, on the legacy server's long lines.
  await viewport(390, 844, false);
  await go(`#/ssh/${by[9462].id}?tab=configuration`);
  await sleep(1200);
  const wide = await js(`return document.documentElement.scrollWidth > window.innerWidth + 1`);
  check('E2E-H.2b', 'an SSH report fits a phone: no sideways scroll (the sshd_config block scrolls inside itself)', !wide);
  await shot('ssh-report-phone');
  await go('#/ssh');
  await sleep(1000);
  const wideList = await js(`return document.documentElement.scrollWidth > window.innerWidth + 1`);
  check('E2E-H.2d', 'SSH servers fits a phone', !wideList);
  await viewport(1440, 900, false);

  // E2E-H.3: the Overview has a card per protocol, each with its own measure, and the scale's per-protocol rules.
  await go('#/');
  await sleep(1400);
  const ov = await text();
  const rules = await js(`return document.querySelector('.level-rules')?.innerText || ''`);
  check('E2E-H.3', 'the Overview shows a TLS endpoints card and an SSH servers card (meeting the baseline, SSH-1), and the scale\'s rules For TLS / For SSH',
    /TLS endpoints/.test(ov) && /SSH servers/.test(ov) && /1 of 6 meet the baseline/.test(ov) && /SSH-1 only/.test(ov) &&
    /How each protocol reaches a level/.test(rules), JSON.stringify({ ov: ov.slice(0, 400) }));
  await shot('overview-protocols');

  // E2E-H.3b: Findings narrows to SSH servers, every place tagged with its protocol.
  await go('#/findings');
  await sleep(1200);
  const fnd = await js(`const sel = document.querySelector('main select[aria-label="Filter by protocol or machine"]');
    sel.value = 'ssh-endpoint'; sel.dispatchEvent(new Event('change'));
    await new Promise((r) => setTimeout(r, 1200));
    for (const d of document.querySelectorAll('details.fgroup')) d.open = true;
    const tags = [...document.querySelectorAll('.fgroup-place .tag')].map((t) => t.innerText);
    return { groups: document.querySelectorAll('details.fgroup').length, tags: [...new Set(tags)], text: document.querySelector('main').innerText.slice(0, 200) }`);
  check('E2E-H.3b', 'Findings filtered to SSH servers lists only SSH places, each tagged SSH',
    fnd.groups > 0 && fnd.tags.length === 1 && fnd.tags[0] === 'SSH', JSON.stringify(fnd));

  // E2E-H.3c: Reports groups documents by protocol.
  await go('#/reports');
  await sleep(1200);
  const rep = await text();
  check('E2E-H.3c', 'Reports has TLS endpoint reports and SSH server reports, SSH rows with the baseline verdict',
    /TLS endpoint reports/.test(rep) && /SSH server reports/.test(rep) && /SSH security report/.test(rep) && /✓ Meets/.test(rep), rep.slice(0, 200));

  // E2E-H.4: Help explains SSH scanning and lists the baseline from the server.
  await go('#/help');
  await sleep(1000);
  const help = await js(`return { ssh: document.querySelector('#help-ssh')?.innerText || '', base: document.querySelector('#help-baseline')?.innerText || '', prot: document.querySelector('#help-protocols')?.innerText || '' }`);
  check('E2E-H.4', 'Help: Protocols (how each is judged), Scan an SSH server (never a login, sshd_config), and the SSH baseline entry by entry',
    /No score/.test(help.prot) && /never a password|no login/i.test(help.ssh) && /sshd_config/.test(help.ssh) &&
    /CipherHorizon SSH baseline 2026 \(default\)/.test(help.base) && /mlkem768x25519-sha256/.test(help.base) && /Requires/.test(help.base),
    JSON.stringify({ base: help.base.slice(0, 200) }));
}
