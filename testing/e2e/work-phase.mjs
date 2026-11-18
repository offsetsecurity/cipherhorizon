// PRD-023 (tracked work, verified closure), driven through the browser on the demo targets: the story
// a migration team lives. An endpoint negotiates classical key exchange; a person plans hybrid key
// exchange from the endpoint's page, records a compatibility test, a second person approves, the change
// is recorded, the product refuses to call it verified until its own scan shows hybrid key exchange,
// the operator really enables it (the demo target's toggle), a rescan runs, and only then is the work
// verified and closed. Then the list, the suggestions, the monitor, the certificate panel, Settings and
// a phone-width check.
import { ADMIN } from './auth-phase.mjs';

const APPROVER = { username: 'e2e-approver', temp: 'temporary pass phrase for approver', password: 'approver chooses a long phrase' };

export async function workPhase({ check, js, go, sleep, shot, api, viewport, CONTROL }) {
  await viewport(1440, 900, false);
  const post = (path, body) => js(`return (async () => { const r = await fetch(${JSON.stringify(path)}, { method: 'POST', headers: { 'X-Requested-With': 'cipherhorizon', 'Content-Type': 'application/json' }, body: ${JSON.stringify(JSON.stringify(body || {}))} }); return { status: r.status, body: await r.text() }; })()`);
  const waitScan = async (assetId, notId) => {
    for (let i = 0; i < 120; i++) {
      const a = await api(`/api/v1/assets/${assetId}`);
      if (a.lastDone && a.lastDone.id !== notId && a.latest?.status === 'done') return a;
      await sleep(500);
    }
    return null;
  };
  const submitModal = async () => { await js(`document.querySelector('.modal form').requestSubmit()`); await sleep(1200); };
  const modalError = () => js(`const e = document.querySelector('.modal [role=alert]'); return e && !e.hidden ? e.textContent : ''`);
  const stage = () => js(`return { current: document.querySelector('.wstage-current .wstage-label')?.textContent || '', side: document.querySelector('.wtrack-side')?.innerText || '',
    verify: document.querySelector('#work-verification .stile-state')?.textContent || '', verifyName: document.querySelector('#work-verification .stile b')?.textContent || '' }`);

  // The toggle target starts classical again (the journey turned it on earlier).
  const off = await fetch(`${CONTROL}/pq/off`, { method: 'POST' });
  const assets = await api('/api/v1/assets?kind=endpoint');
  const target = assets.find((a) => a.port === 9445);
  await post(`/api/v1/assets/${target.id}/scan`);
  const classical = await waitScan(target.id, target.lastDone?.id);
  check('E2E-WK.pre', 'the toggle endpoint is classical again (L1) before the story starts', off.ok && classical?.lastDone?.readinessLevel === 1, classical?.lastDone?.readinessLevel);

  // E2E-WK.1: the endpoint page offers to plan hybrid key exchange; the dialog says how it will be closed.
  await go(`#/endpoints/${target.id}`);
  await sleep(1200);
  const plan = await js(`return document.querySelector('[data-track=readiness]')?.textContent || ''`);
  await js(`document.querySelector('[data-track=readiness]').click()`);
  await sleep(900);
  const dlg = await js(`return { title: document.getElementById('track-title')?.value || '', flow: document.getElementById('track-workflow')?.value || '',
    purpose: document.getElementById('track-purpose')?.textContent || '', text: document.querySelector('.modal')?.innerText || '' }`);
  await shot('work-track-dialog', { full: false });
  check('E2E-WK.1', 'the endpoint page offers Plan hybrid key exchange; the dialog proposes the post-quantum key exchange workflow and says it closes as verified only on a later scan',
    plan === 'Plan hybrid key exchange' && dlg.flow === 'pq-key-exchange' && /hybrid key exchange/.test(dlg.title) && /verified only when a later scan/.test(dlg.purpose),
    JSON.stringify({ plan, ...dlg }));
  await js(`document.getElementById('track-owner').value = 'platform team'; document.getElementById('track-project').value = 'PQC wave 1';
    document.getElementById('track-due').value = '2099-03-31';`);
  await submitModal();
  await sleep(800);
  const workId = Number(await js(`return (/^#\\/work\\/(\\d+)$/.exec(location.hash) || [])[1] || 0`));
  let st = await stage();
  await shot('work-item-new');
  check('E2E-WK.2', 'creating it opens the work: Requested is the current stage, Verified by scan lies ahead, and verification has not started',
    workId > 0 && st.current === 'Requested' && /Not checked yet/.test(st.verifyName) && /recorded as made/.test(st.verify), JSON.stringify({ workId, ...st }));

  // E2E-WK.3: a step that needs evidence is not taken without it.
  await js(`document.querySelector('[data-transition=test]').click()`);
  await sleep(600);
  await js(`document.getElementById('move-evidence').removeAttribute('required'); document.getElementById('move-evidence').value = '   '`);
  await submitModal();
  const noEvidence = await modalError();
  await js(`document.getElementById('move-evidence').value = 'CHG-2041: Chrome 131, Firefox 133 and curl 8.11 negotiate X25519MLKEM768 on staging'`);
  await submitModal();
  st = await stage();
  check('E2E-WK.3', 'recording the compatibility test without evidence is refused in words; with evidence the work moves on',
    /needs evidence/.test(noEvidence) && st.current === 'Client compatibility tested', JSON.stringify({ noEvidence, ...st }));

  // E2E-WK.4: the person who asked for the work cannot approve it.
  await js(`document.querySelector('[data-transition=approve]').click()`);
  await sleep(600);
  await submitModal();
  const selfApprove = await modalError();
  await shot('work-approval-refused', { full: false });
  await js(`document.querySelector('.modal .icon-btn')?.click()`);
  check('E2E-WK.4', 'the requester’s own approval is refused, with the reason', /cannot approve/.test(selfApprove), selfApprove);

  // E2E-WK.5: a second person signs in and approves.
  const made = await post('/api/v1/users', { username: APPROVER.username, role: 'analyst', password: APPROVER.temp });
  await js(`return (async () => {
    await fetch('/api/v1/auth/logout', { method: 'POST', headers: { 'X-Requested-With': 'cipherhorizon' } });
    await fetch('/api/v1/auth/login', { method: 'POST', headers: { 'X-Requested-With': 'cipherhorizon', 'Content-Type': 'application/json' }, body: JSON.stringify({ username: '${APPROVER.username}', password: '${APPROVER.temp}' }) });
    await fetch('/api/v1/auth/password', { method: 'POST', headers: { 'X-Requested-With': 'cipherhorizon', 'Content-Type': 'application/json' }, body: JSON.stringify({ current: '${APPROVER.temp}', new: '${APPROVER.password}' }) });
    return true; })()`);
  await js(`location.reload()`);
  await sleep(2000);
  await go(`#/work/${workId}`);
  await sleep(1200);
  await js(`document.querySelector('[data-transition=approve]').click()`);
  await sleep(600);
  await submitModal();
  st = await stage();
  const approvedBy = await js(`return [...document.querySelectorAll('.work-kv dt')].find((d) => d.textContent === 'Approved by')?.nextElementSibling?.textContent || ''`);
  check('E2E-WK.5', 'a second signed-in person approves; the work says who', made.status === 201 && st.current === 'Approved' && approvedBy === APPROVER.username,
    JSON.stringify({ made: made.status, ...st, approvedBy }));

  // E2E-WK.6: recording the change does not verify it; the product waits for its own scan.
  await js(`document.querySelector('[data-transition=enable]').click()`);
  await sleep(600);
  await js(`document.getElementById('move-note').value = 'ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1 on the portal'`);
  await submitModal();
  await js(`document.querySelector('[data-transition=verify]').click()`);
  await sleep(600);
  await submitModal();
  const waiting = await modalError();
  await js(`document.querySelector('.modal .icon-btn')?.click()`);
  await sleep(400);
  check('E2E-WK.6', 'after the change is recorded, Verify is refused until a scan has run since: the product does not take the word for it',
    /not verified/.test(waiting) && /no scan of .* has finished since/.test(waiting), waiting);

  // E2E-WK.7: a scan of the unchanged endpoint says so, with the level it found.
  await js(`document.getElementById('work-scan').click()`);
  await sleep(1500);
  await waitScan(target.id, classical.lastDone.id);
  await js(`document.getElementById('work-check').click()`);
  await sleep(1200);
  st = await stage();
  await shot('work-not-verified');
  check('E2E-WK.7', 'the endpoint was not really changed: a rescan finds L1 and the verification says Not verified, target L3',
    /Not verified/.test(st.verifyName) && /target is L3/.test(st.verify), JSON.stringify(st));

  // E2E-WK.8: the operator really enables hybrid key exchange; the next scan verifies it.
  const on = await fetch(`${CONTROL}/pq/on`, { method: 'POST' });
  const before = await api(`/api/v1/assets/${target.id}`);
  await js(`document.getElementById('work-scan').click()`);
  await sleep(1500);
  const after = await waitScan(target.id, before.lastDone.id);
  await js(`document.getElementById('work-check').click()`);
  await sleep(1200);
  const checked = await stage();
  await js(`document.querySelector('[data-transition=verify]').click()`);
  await sleep(600);
  await submitModal();
  await js(`document.querySelector('[data-transition=close]').click()`);
  await sleep(600);
  await submitModal();
  st = await stage();
  const hist = await js(`return [...document.querySelectorAll('#work-history .timeline-what')].map((e) => e.innerText.split('\\n')[0]).reverse()`);
  await shot('work-item-verified');
  check('E2E-WK.8', 'with hybrid key exchange really enabled, a rescan reaches L3, the verification says Verified and the work closes',
    on.ok && after?.lastDone?.readinessLevel === 3 && /^Verified$/.test(checked.verifyName) && /reached L3/.test(checked.verify) && st.current === 'Closed',
    JSON.stringify({ level: after?.lastDone?.readinessLevel, checked, st }));
  check('E2E-WK.9', 'the history reads as the story, in the workflow’s words, with both people',
    hist.length === 6 && /^Created by/.test(hist[0]) && /^Record the compatibility test by/.test(hist[1]) && new RegExp(`^Approve by ${APPROVER.username}`).test(hist[2]) &&
    /^Record that it is enabled/.test(hist[3]) && /^Verify by/.test(hist[4]) && /Verified/.test(hist[4]) && /^Close by/.test(hist[5]), JSON.stringify(hist));

  // E2E-WK.10: the list counts it as verified, out of its denominator; the evidence pack carries it.
  await go('#/work?view=verified');
  await sleep(1500);
  const list = await js(`return { band: document.querySelector('.statusband')?.innerText || '', rows: document.querySelectorAll('#work-table tbody tr').length,
    readiness: [...document.querySelectorAll('.work-pipeline')].map((e) => e.innerText).join(' | ') }`);
  const pack = await js(`return (async () => { const r = await fetch('/api/v1/work/evidence.json'); const j = await r.json();
    const w = j.work.find((x) => x.item.id === ${workId}); return { status: r.status, verifiedNow: w?.verificationNow?.status, steps: w?.history?.length, catalog: j.catalogVersion }; })()`);
  await shot('work-list-verified');
  check('E2E-WK.10', 'the Work list counts the closed work as verified by scan, says out of what, and lists it; the evidence pack carries its 6 steps and verifies it again at export',
    /Verified by scan\s*\n?\s*\d+/.test(list.band) && list.rows >= 1 && /scanned endpoints/.test(list.readiness) && /not scanned/.test(list.readiness) &&
    pack.status === 200 && pack.verifiedNow === 'verified' && pack.steps === 6 && !!pack.catalog, JSON.stringify({ list, pack }));

  // E2E-WK.11: suggestions come from the scans and cite their basis; needs-attention is explained.
  await go('#/work?tab=suggested');
  await sleep(1200);
  const sugg = await js(`return { rows: document.querySelectorAll('#suggestion-table tbody tr').length, text: document.querySelector('#suggestion-table')?.innerText || '' }`);
  await shot('work-suggested');
  check('E2E-WK.11', 'Suggested lists work the scans point at, the classical endpoints among them, each citing NIST IR 8547 where a date applies',
    sugg.rows > 0 && /hybrid key exchange/.test(sugg.text) && /NIST IR 8547/.test(sugg.text),
    sugg.text.slice(0, 600));
  await go('#/work?tab=attention');
  await sleep(1000);
  const attn = await js(`return document.querySelector('main')?.innerText || ''`);
  check('E2E-WK.12', 'Needs attention lists events in words or says plainly that nothing needs a person', /Nothing needs a person|What the lifecycle monitor finds now/.test(attn), attn.slice(0, 300));

  // E2E-WK.13: a regression is caught: the operator turns hybrid off again.
  await fetch(`${CONTROL}/pq/off`, { method: 'POST' });
  const last = await api(`/api/v1/assets/${target.id}`);
  await post(`/api/v1/assets/${target.id}/scan`);
  await waitScan(target.id, last.lastDone.id);
  await go('#/work'); // the page is already on the attention tab: leave it so that it is drawn again
  await sleep(600);
  await go('#/work?tab=attention');
  await sleep(1200);
  const reg = await js(`return document.querySelector('#attention-table tr[data-kind="work.regressed"]')?.innerText || ''`);
  await shot('work-regression');
  check('E2E-WK.13', 'turning hybrid key exchange off again is caught: Needs attention shows the verified work no longer holds, as critical',
    /No longer holds/.test(reg) && /critical/.test(reg), reg);

  // Back to the administrator for the settings checks.
  await js(`return (async () => {
    await fetch('/api/v1/auth/logout', { method: 'POST', headers: { 'X-Requested-With': 'cipherhorizon' } });
    await fetch('/api/v1/auth/login', { method: 'POST', headers: { 'X-Requested-With': 'cipherhorizon', 'Content-Type': 'application/json' }, body: JSON.stringify({ username: '${ADMIN.username}', password: '${ADMIN.password}' }) });
    return true; })()`);
  await js(`location.reload()`);
  await sleep(2000);

  // E2E-WK.14: Settings holds Notifications and Integrations; planned connectors are labelled planned.
  await go('#/settings');
  await sleep(1500);
  const set = await js(`return { notify: document.getElementById('set-notify')?.innerText || '', integ: document.getElementById('set-integrations')?.innerText || '',
    planned: document.querySelectorAll('#set-integrations details tbody tr').length }`);
  await shot('settings-notifications');
  check('E2E-WK.14', 'Settings has Notifications (expiry windows, webhook, secret by environment variable) and Integrations (scanner and webhook available; the rest listed as planned)',
    /Certificate expiry warning/.test(set.notify) && /environment variable/.test(set.notify) && /Webhook/.test(set.integ) && /scanner/.test(set.integ) && set.planned >= 5,
    JSON.stringify({ planned: set.planned, notify: set.notify.slice(0, 200) }));

  // E2E-WK.15: a certificate page shows its owner and renewal and can plan its renewal.
  const certs = await api('/api/v1/certificates');
  const leaf = (certs.certificates || []).find((c) => c.role === 'end-entity' && (c.origins || []).includes('scanner'));
  await go(`#/certificates/${leaf.fingerprint}`);
  await sleep(1500);
  await js(`document.getElementById('cert-life-edit').click()`);
  await sleep(500);
  await js(`document.getElementById('life-owner').value = 'PKI team'; document.getElementById('life-renewal').value = 'acme';`);
  await submitModal();
  const life = await js(`return { text: document.getElementById('cert-lifecycle')?.innerText || '', plan: !!document.getElementById('cert-plan') }`);
  await shot('certificate-ownership');
  check('E2E-WK.15', 'a certificate shows who owns it and how it is renewed, editable, with Plan renewal', /PKI team/.test(life.text) && /ACME/.test(life.text) && life.plan,
    JSON.stringify(life));

  // E2E-WK.16: the work pages fit a phone.
  await viewport(390, 844, true);
  const fits = {};
  for (const [name, at] of [['list', '#/work'], ['item', `#/work/${workId}`]]) {
    await go(at);
    await sleep(1200);
    fits[name] = await js(`return document.documentElement.scrollWidth - document.documentElement.clientWidth`);
    await shot(`work-${name}-390`);
  }
  await viewport(1440, 900, false);
  check('E2E-WK.16', 'the Work list and a piece of work fit a 390px screen without sideways scrolling', Object.values(fits).every((o) => o <= 1), JSON.stringify(fits));
  await fetch(`${CONTROL}/pq/off`, { method: 'POST' });
}
