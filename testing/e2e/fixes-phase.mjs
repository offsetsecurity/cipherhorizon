// Fixes and Renewals (UX-DESIGN-024), driven through the browser on the demo targets: the whole job
// as a customer does it. An endpoint negotiates classical key exchange; a person assigns the fix from
// its page (who, by when, a ticket link) and does nothing else. A scan of the unchanged endpoint says
// not fixed; the operator really enables post-quantum key exchange (the demo target's toggle); the next
// scan says fixed, by itself; the change is undone and the next scan brings it back.

export async function fixesPhase({ check, js, go, sleep, shot, api, viewport, CONTROL }) {
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
  const state = () => js(`return { big: document.querySelector('#fix-state .fixstate-big')?.textContent || '', line: document.querySelector('#fix-state .fixstate-line')?.textContent || '',
    buttons: [...document.querySelectorAll('main button')].map((b) => b.textContent.trim()) }`);
  const waitState = async (re) => { for (let i = 0; i < 80; i++) { const s = await state(); if (re.test(s.big)) return s; await sleep(500); } return state(); };

  const off = await fetch(`${CONTROL}/pq/off`, { method: 'POST' });
  const assets = await api('/api/v1/assets?kind=endpoint');
  const target = assets.find((a) => a.port === 9445);
  await post(`/api/v1/assets/${target.id}/scan`);
  const classical = await waitScan(target.id, target.lastDone?.id);
  check('E2E-FX.pre', 'the toggle endpoint is classical again (L1) before the story starts', off.ok && classical?.lastDone?.readinessLevel === 1, classical?.lastDone?.readinessLevel);

  // E2E-FX.1: one button on the endpoint, one small form.
  await go(`#/endpoints/${target.id}`);
  await sleep(1200);
  const btn = await js(`return document.querySelector('[data-assign=readiness]')?.textContent || ''`);
  await js(`document.querySelector('[data-assign=readiness]').click()`);
  await sleep(700);
  const dlg = await js(`const m = document.querySelector('.modal'); return { title: m?.querySelector('h2')?.textContent || '', labels: [...(m?.querySelectorAll('label') || [])].map((l) => l.textContent.trim()),
    note: m?.querySelector('.assign-note')?.textContent || '', inputs: m?.querySelectorAll('input, select, textarea').length }`);
  await shot('fixes-assign-form', { full: false });
  check('E2E-FX.1', 'an endpoint below hybrid key exchange offers Assign the fix; the form asks only who, by when and an optional ticket link, and says that is all there is to do',
    btn === 'Assign the fix' && dlg.title === 'Assign this fix' && dlg.inputs === 3 && /Who will fix it/.test(dlg.labels.join()) && /By when/.test(dlg.labels.join()) &&
    /Your ticket/.test(dlg.labels.join()) && /That is all you do here/.test(dlg.note), JSON.stringify({ btn, ...dlg }));

  // E2E-FX.2: assigning opens the fix; nothing on it lets a person say it is fixed.
  await js(`document.getElementById('assign-owner').value = 'Platform team'; document.getElementById('assign-due').value = '2099-03-31';
    document.getElementById('assign-ticket').value = 'https://tracker.example.com/CHG-2041'; document.querySelector('.modal form').requestSubmit()`);
  await sleep(1800);
  const fixId = Number(await js(`return (/^#\\/fixes\\/(\\d+)$/.exec(location.hash) || [])[1] || 0`));
  let st = await state();
  const head = await js(`return { h1: document.getElementById('fix-h1')?.textContent || '', sub: document.querySelector('.page-head .sub')?.innerText || '', nav: document.querySelector('#nav a[aria-current=page]')?.innerText.trim() || '',
    text: document.querySelector('main').innerText }`);
  await shot('fix-new');
  check('E2E-FX.2', 'the fix opens named in plain words with its owner, date and ticket; it is not checked yet, and no button claims it is fixed',
    fixId > 0 && /Post-quantum key exchange on/.test(head.h1) && /Platform team/.test(head.sub) && /Your ticket/.test(head.sub) && head.nav === 'Fixes' &&
    /Not checked yet/.test(st.big) && !st.buttons.some((b) => /verif|mark.*(fixed|done)|approve/i.test(b)) && /Nobody can mark it fixed by hand/.test(head.text),
    JSON.stringify({ fixId, st, h1: head.h1, sub: head.sub }));
  check('E2E-FX.2b', 'the page speaks the customer’s language: no workflow, stage, transition, marker or verification anywhere on it',
    !/workflow|\\bstage\\b|transition|marker|verif|baseline/i.test(head.text), head.text.match(/workflow|\\bstage\\b|transition|marker|verif\\w*|baseline/i)?.[0] || '');

  // E2E-FX.3: a scan of the unchanged endpoint: not fixed yet.
  await js(`document.getElementById('fix-scan').click()`);
  st = await waitState(/Not fixed yet/);
  check('E2E-FX.3', 'Scan now on the unchanged endpoint: the page updates by itself to Not fixed yet', /Not fixed yet/.test(st.big) && /Checked/.test(st.line), JSON.stringify(st));

  // E2E-FX.4: the operator really enables it; the next scan marks it fixed with nobody pressing more.
  const on = await fetch(`${CONTROL}/pq/on`, { method: 'POST' });
  await js(`document.getElementById('fix-scan').click()`);
  st = await waitState(/^Fixed$/);
  const hist = await js(`return [...document.querySelectorAll('#fix-history .fixhist li')].map((li) => li.lastElementChild.textContent)`);
  await shot('fix-fixed');
  check('E2E-FX.4', 'with post-quantum key exchange really enabled, the next scan turns the fix to Fixed, confirmed by the scan of today; the history says a scan confirmed it',
    on.ok && st.big === 'Fixed' && /Confirmed by the scan of/.test(st.line) && hist.some((x) => /A scan confirmed it is fixed/.test(x)) && hist.some((x) => /^Assigned by/.test(x)),
    JSON.stringify({ st, hist }));

  // E2E-FX.5: the list: progress out of scanned endpoints, sections in plain words, Assign on what is next.
  await go('#/fixes');
  await sleep(1500);
  await js(`document.getElementById('fixes-show-fixed')?.click()`);
  await sleep(600);
  const list = await js(`return { progress: document.getElementById('fix-progress')?.textContent || '', heads: [...document.querySelectorAll('main h2')].map((x) => x.textContent.trim()),
    fixed: [...document.querySelectorAll('#fixes-fixed [data-fix]')].map((li) => li.innerText), next: document.querySelectorAll('#fixes-next [data-assign]').length,
    text: document.querySelector('main').innerText }`);
  await shot('fixes-list');
  check('E2E-FX.5', 'Fixes shows progress out of scanned endpoints, To fix next with an Assign button per line, and the fix under Fixed and still holding',
    /of \\d+ scanned endpoints? keeps? today’s traffic safe/.test(list.progress) && list.heads.some((x) => /^To fix next/.test(x)) && list.next > 0 &&
    list.fixed.some((t) => /Post-quantum key exchange on/.test(t) && /Fixed\\. Confirmed by the scan/.test(t)) && !/workflow|\\bstage\\b|transition|verif/i.test(list.text),
    JSON.stringify({ progress: list.progress, heads: list.heads, next: list.next, fixed: list.fixed }));

  // E2E-FX.6: the change is undone; the next scan brings the fix back to the top.
  await fetch(`${CONTROL}/pq/off`, { method: 'POST' });
  const last = await api(`/api/v1/assets/${target.id}`);
  await post(`/api/v1/assets/${target.id}/scan`);
  await waitScan(target.id, last.lastDone.id);
  await go('#/');
  await sleep(400);
  await go('#/fixes');
  await sleep(1500);
  const back = await js(`return { first: document.querySelector('main h2')?.textContent.trim() || '', row: document.querySelector('#fixes-back [data-fix]')?.innerText || '' }`);
  await shot('fixes-came-back');
  check('E2E-FX.6', 'undoing the change is caught by the next scan: Came back is the first section, and says a scan found it again',
    /^Came back/.test(back.first) && /Post-quantum key exchange on/.test(back.row) && /Was fixed\\. The scan of .* found it again/.test(back.row), JSON.stringify(back));

  // E2E-FX.7: not now: on hold with a reason and a date.
  await go(`#/fixes/${fixId}`);
  await sleep(1200);
  await js(`document.getElementById('fix-hold').click()`);
  await sleep(500);
  const until = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
  await js(`document.getElementById('hold-why').value = 'change freeze until the new year'; document.getElementById('hold-until').value = '${until}'; document.querySelector('.modal form').requestSubmit()`);
  st = await waitState(/On hold/);
  check('E2E-FX.7', 'Put on hold takes a reason and a date; the fix reads On hold until that date and offers Resume now',
    st.big === 'On hold' && /On hold until/.test(st.line) && st.buttons.includes('Resume now'), JSON.stringify(st));

  // E2E-FX.8: Renewals: certificates by date, assigned the same way.
  await go('#/renewals');
  await sleep(1500);
  const ren = await js(`return { h1: document.querySelector('main h1')?.textContent || '', line: document.getElementById('renew-line')?.textContent || '', rows: document.querySelectorAll('[data-cert]').length,
    bars: document.querySelectorAll('.renewbar-col').length, assign: document.querySelectorAll('[data-cert] [data-assign=certificate]').length, nav: document.querySelector('#nav a[aria-current=page]')?.innerText.trim() || '' }`);
  await js(`document.querySelector('#renew-soon [data-cert] [data-assign=certificate]')?.click()`);
  await sleep(600);
  await js(`document.getElementById('assign-owner').value = 'PKI team'; document.querySelector('.modal form')?.requestSubmit()`);
  await sleep(1800);
  const assigned = await js(`return [...document.querySelectorAll('[data-cert]')].map((li) => li.innerText).find((t) => /PKI team/.test(t)) || ''`);
  await shot('renewals');
  check('E2E-FX.8', 'Renewals lists every served certificate by date with four months of bars; assigning a renewal uses the same form and the row then names who has it',
    ren.h1 === 'Renewals' && ren.rows > 0 && ren.bars === 4 && ren.assign > 0 && ren.nav === 'Renewals' && /out in the next \\d+ days/.test(ren.line) && /PKI team/.test(assigned),
    JSON.stringify({ ...ren, assigned }));

  // E2E-FX.9: a certificate's page says who owns it and how it is renewed.
  const certs = await api('/api/v1/renewals');
  const withFix = (certs.certificates || []).find((c) => c.fix);
  await go(`#/certificates/${withFix?.fingerprint}`);
  await sleep(1500);
  await js(`document.getElementById('cert-life-edit').click()`);
  await sleep(500);
  await js(`document.getElementById('life-owner').value = 'PKI team'; document.getElementById('life-renewal').value = 'acme'; document.querySelector('.modal form').requestSubmit()`);
  await sleep(1500);
  const life = await js(`return document.getElementById('cert-lifecycle')?.innerText || ''`);
  check('E2E-FX.9', 'a certificate shows its owner, how it is renewed, and the renewal assigned for it', /PKI team/.test(life) && /ACME/.test(life) && /Renew the certificate of/.test(life), life);

  // E2E-FX.10: Settings holds Notifications and Integrations; planned connectors are labelled planned.
  await go('#/settings');
  await sleep(1500);
  const set = await js(`return { notify: document.getElementById('set-notify')?.innerText || '', integ: document.getElementById('set-integrations')?.innerText || '',
    planned: document.querySelectorAll('#set-integrations details tbody tr').length, switches: [...document.querySelectorAll('#set-notify .setrow-label')].map((l) => l.textContent.trim()).filter(Boolean).length }`);
  await shot('settings-notifications');
  check('E2E-FX.10', 'Settings has Notifications (windows, webhook, secret by environment variable, eight named events) and Integrations (the scanner and the webhook available; the rest listed as planned)',
    /Certificate expiry warning/.test(set.notify) && /environment variable/.test(set.notify) && set.switches === 8 && /Webhook/.test(set.integ) && set.planned >= 5,
    JSON.stringify({ planned: set.planned, switches: set.switches }));

  // E2E-FX.11: the pages fit a phone.
  await viewport(390, 844, true);
  const fits = {};
  for (const [name, at] of [['fixes', '#/fixes'], ['fix', `#/fixes/${fixId}`], ['renewals', '#/renewals']]) {
    await go(at);
    await sleep(1200);
    fits[name] = await js(`return document.documentElement.scrollWidth - document.documentElement.clientWidth`);
    await shot(`${name}-390`);
  }
  await viewport(1440, 900, false);
  check('E2E-FX.11', 'Fixes, one fix and Renewals fit a 390px screen without sideways scrolling', Object.values(fits).every((o) => o <= 1), JSON.stringify(fits));
  await fetch(`${CONTROL}/pq/off`, { method: 'POST' });
}
