// PRD-008 (post-quantum signatures and SSH endpoints), driven through the browser on demo-targets:
// SSH servers from base+20 (9460 hybrid, 9461 classical, 9462 legacy, 9463 ML-DSA host key,
// 9465 SSH-1), and the ML-DSA TLS servers at 9458 (ML-DSA only) and 9459 (ECDSA + ML-DSA).

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
  await viewport(1440, 900, false);

  // E2E-H.1: the add dialog's Protocol choice, and ssh:// in a pasted list.
  await go('#/endpoints');
  await sleep(700);
  await clickText('Add endpoints');
  await sleep(300);
  await js(`document.getElementById('add-target').value = '127.0.0.1:9460'; document.getElementById('add-protocol').value = 'ssh';
    document.getElementById('add-name').value = 'bastion-hybrid'; document.querySelector('.modal form').requestSubmit();`);
  await sleep(1000);
  await js(`return fetch('/api/v1/assets/bulk', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'cipherhorizon' },
    body: JSON.stringify({ text: 'ssh://127.0.0.1:9461\nssh://127.0.0.1:9462\nssh://127.0.0.1:9463\nssh://127.0.0.1:9465\n127.0.0.1:9458\n127.0.0.1:9459' }) }).then((r) => r.json())`);
  const all = await js(`return (await fetch('/api/v1/assets?kind=endpoint')).json()`);
  const by = Object.fromEntries(all.filter((a) => a.port >= 9458 && a.port <= 9465).map((a) => [a.port, a]));
  check('E2E-H.1', 'an SSH endpoint is added by choosing SSH in the dialog and by ssh:// in a list',
    by[9460]?.protocol === 'ssh' && by[9460]?.name === 'bastion-hybrid' && [9461, 9462, 9463, 9465].every((p) => by[p]?.protocol === 'ssh') && by[9458]?.protocol === 'tls',
    JSON.stringify(Object.values(by).map((a) => `${a.port}:${a.protocol}`)));
  for (const p of [9460, 9461, 9462, 9463, 9465, 9458, 9459]) await scan(by[p].id);
  const done = {};
  for (const p of [9460, 9461, 9462, 9463, 9465, 9458, 9459]) done[p] = await waitDone(by[p].id);
  const lvl = (p) => done[p]?.lastDone?.readinessLevel;
  check('E2E-H.1b', 'SSH demo servers land on their levels: hybrid L3, classical L1, ML-DSA host key L4, SSH-1 L0; the legacy one is Weak or Broken',
    lvl(9460) === 3 && lvl(9461) === 1 && lvl(9463) === 4 && lvl(9465) === 0 && ['Weak', 'Broken'].includes(done[9462]?.lastDone?.band),
    JSON.stringify([9460, 9461, 9462, 9463, 9465].map((p) => [p, lvl(p), done[p]?.lastDone?.band])));

  // E2E-H.1c: the list says SSH and the software, with the host key in the key column; the filter keeps only SSH.
  await go('#/endpoints');
  await sleep(1000);
  const list = await js(`const rows = [...document.querySelectorAll('main tbody tr')].map((r) => r.innerText);
    const sel = document.querySelector('main select[aria-label="Protocol"]'); sel.value = 'ssh'; sel.dispatchEvent(new Event('change'));
    await new Promise((r) => setTimeout(r, 300));
    return { rows, filtered: [...document.querySelectorAll('main tbody tr')].map((r) => r.innerText), head: document.querySelector('main thead').innerText }`);
  check('E2E-H.1c', 'Endpoints shows "SSH · <software>" and the host key type, says Hygiene and Certificate / key, and filters to SSH',
    list.rows.some((r) => /SSH · Go/.test(r) && /Ed25519 host key/.test(r)) && /Hygiene/.test(list.head) && /Certificate \/ key/.test(list.head) &&
    list.filtered.length >= 5 && list.filtered.every((r) => /SSH/.test(r)), JSON.stringify({ head: list.head, n: list.filtered.length }));
  await shot('ssh-endpoints');

  // E2E-H.2: every tab of an SSH report renders, in SSH's words.
  await go(`#/endpoints/${by[9460].id}`);
  await sleep(1400);
  const tabs = {};
  for (const t of ['summary', 'configuration', 'weaknesses', 'cbom', 'history']) {
    await go(`#/endpoints/${by[9460].id}?tab=${t}`);
    await sleep(t === 'cbom' ? 1800 : 900);
    tabs[t] = await js(`return document.querySelector('main').innerText`);
    if (t !== 'history') await shot(`ssh-report-${t}`);
  }
  const noTLSWords = Object.entries(tabs).every(([t, txt]) => !/TLS hygiene|cipher suite|certificate chain/i.test(txt));
  check('E2E-H.2', 'an SSH report: SSH hygiene, Host key tile, SSH areas, per-algorithm verdicts, every check, an ssh CBOM, and no TLS words',
    /SSH hygiene/.test(tabs.summary) && /Host key/.test(tabs.summary) && /SSH version & software/.test(tabs.summary) &&
    /mlkem768x25519-sha256/.test(tabs.configuration) && /used by OpenSSH 10\.6/.test(tabs.configuration) && /Offered · post-quantum/.test(tabs.configuration) &&
    /checks run/.test(tabs.weaknesses) && /SSH-2\.0/.test(tabs.cbom) && noTLSWords,
    JSON.stringify({ summary: tabs.summary.slice(0, 160), noTLSWords }));

  // E2E-H.2b: phone width, no sideways scroll.
  await viewport(390, 844, false);
  await go(`#/endpoints/${by[9462].id}?tab=configuration`);
  await sleep(1200);
  const wide = await js(`return document.documentElement.scrollWidth > window.innerWidth + 1`);
  check('E2E-H.2b', 'an SSH report fits a phone: no sideways scroll', !wide);
  await shot('ssh-report-phone');
  await viewport(1440, 900, false);

  // E2E-H.3: the Overview counts SSH and its scale speaks for both protocols.
  await go('#/');
  await sleep(1200);
  const ov = await js(`return document.querySelector('main').innerText`);
  check('E2E-H.3', 'the Overview scale covers SSH (SSH-1 in L0, host key in L4) and its placeholder offers ssh://',
    /SSH-1/.test(ov) && /host key/.test(ov) && /ssh:\/\//.test(await js(`return document.querySelector('#scan-target')?.placeholder || ''`)), ov.slice(0, 200));

  // E2E-H.4: Help explains SSH scanning.
  await go('#/help');
  await sleep(800);
  const help = await js(`return document.querySelector('#help-ssh')?.innerText || ''`);
  check('E2E-H.4', 'Help has "Scan an SSH server": what is sent (never a login), the readiness rules and sshd_config',
    /never a password|no login/i.test(help) && /sshd_config/.test(help) && /OpenSSH 10\.6/.test(help), help.slice(0, 160));

  // E2E-S.1: post-quantum certificates in TLS (WP-A): both ML-DSA demo servers are L4, the signature table shows ML-DSA-65.
  await go(`#/endpoints/${by[9459].id}?tab=configuration`);
  await sleep(1400);
  const sig = await js(`return document.querySelector('main').innerText`);
  check('E2E-S.1', 'the ML-DSA-only and the dual-certificate TLS servers are L4, and the signature schemes list mldsa65 as accepted',
    lvl(9458) === 4 && lvl(9459) === 4 && /Signature schemes the server can authenticate with/.test(sig) && /mldsa65/.test(sig) && /Accepted · post-quantum \(ML-DSA-65\)/.test(sig),
    JSON.stringify({ l: [lvl(9458), lvl(9459)] }));
  await shot('tls-signature-schemes');
}
