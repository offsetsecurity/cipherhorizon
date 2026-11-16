// PRD-022 (find endpoints from a domain), driven through the browser. The journey's server has no
// zone of its own, so the search runs on journey.invalid: a domain that by RFC 2606 never
// resolves. That covers the form, the opt-in of certificate logs, a run from start to result, the
// review list and the honest statement of what was not seen. What answers and gets added is
// covered by the server's own tests, which have a zone.

export async function discoverPhase({ check, js, go, sleep, shot, viewport }) {
  await viewport(1440, 900, false);

  // E2E-DD.1: the list pages lead to the form; certificate logs are off until Settings says so.
  await go('#/endpoints');
  await sleep(800);
  const entry = await js(`return document.getElementById('endpoints-discover')?.getAttribute('href') || ''`);
  await go('#/discover');
  await sleep(900);
  const form = await js(`return { h1: document.querySelector('main h1')?.innerText || '', ctDisabled: document.getElementById('disc-src-ct')?.disabled,
    ctText: document.getElementById('disc-src-ct')?.closest('.setrow')?.innerText || '', dns: document.getElementById('disc-src-dns')?.checked,
    wordlist: document.getElementById('disc-src-wordlist')?.checked, nav: document.querySelector('#nav a[aria-current=page]')?.innerText.trim() || '' }`);
  await shot('discover-form');
  check('E2E-DD.1', 'TLS endpoints leads to Find from a domain; DNS records are on, common names off, and certificate logs cannot be ticked until an administrator turns them on',
    entry === '#/discover' && form.h1 === 'Find from a domain' && form.ctDisabled === true && /Turned off/.test(form.ctText) && /Settings/.test(form.ctText) &&
    form.dns === true && form.wordlist === false && /TLS endpoints/.test(form.nav), JSON.stringify({ entry, ...form }));

  // E2E-DD.2: a bad domain is refused in words, on the form.
  await js(`document.getElementById('disc-domain').value = 'https://journey.invalid/x'; document.querySelector('.discover-form').requestSubmit()`);
  await sleep(700);
  const bad = await js(`return { err: document.querySelector('.discover-form [role=alert]')?.innerText || '', hash: location.hash }`);
  check('E2E-DD.2', 'a URL in place of a domain is refused with the reason, and nothing starts',
    /without a scheme, port or path/.test(bad.err) && bad.hash === '#/discover', JSON.stringify(bad));

  // E2E-DD.3: a search runs to a result; names that do not resolve are listed, none can be added.
  await js(`document.getElementById('disc-domain').value = 'journey.invalid'; document.querySelector('.discover-list').open = true;
    document.getElementById('disc-list').value = ['www.journey.invalid', 'mail.journey.invalid', 'elsewhere.example'].join(String.fromCharCode(10));
    document.querySelector('.discover-form').requestSubmit()`);
  let run = null;
  for (let i = 0; i < 120; i++) {
    await sleep(500);
    const id = await js(`return (/^#\\/discover\\/(\\d+)$/.exec(location.hash) || [])[1] || ''`);
    if (!id) continue;
    run = await js(`return (await fetch('/api/v1/discoveries/${id}')).json()`);
    if (run.discovery && run.discovery.status !== 'running') break;
  }
  await sleep(1800);
  const page = await js(`return { text: document.querySelector('main').innerText, rows: document.querySelectorAll('table.discover-names tbody tr').length,
    boxes: [...document.querySelectorAll('table.discover-names tbody input[type=checkbox]')].filter((b) => !b.disabled).length,
    accept: document.getElementById('disc-accept')?.disabled, acceptText: document.getElementById('disc-accept')?.innerText || '' }`);
  await shot('discover-result');
  check('E2E-DD.3', 'the search ends Done with the domain and the two listed names, none resolving; nothing can be chosen and the add button says so',
    run?.discovery?.status === 'done' && run.names.length === 3 && run.names.every((n) => n.addresses.length === 0) &&
    page.rows === 3 && page.boxes === 0 && page.accept === true && /Choose names to add/.test(page.acceptText) && /Does not resolve/.test(page.text),
    JSON.stringify({ status: run?.discovery?.status, names: run?.names?.map((n) => n.name), rows: page.rows, boxes: page.boxes, accept: page.acceptText }));
  check('E2E-DD.3b', 'the result says where it looked and what it could not see: the name outside the domain was left out, certificate logs were not searched, and no source is complete',
    /Where the names came from/.test(page.text) && /1 supplied name is not under journey\.invalid/.test(page.text) &&
    /Certificate logs were not searched/.test(page.text) && /Your own DNS zone is the complete list/.test(page.text), page.text.slice(-900));

  // E2E-DD.4: nothing was added, and the search is kept and listed.
  const after = await js(`return { endpoints: (await (await fetch('/api/v1/assets?kind=endpoint')).json()).filter((a) => /journey\\.invalid$/.test(a.host)).length }`);
  await go('#/discover');
  await sleep(900);
  const earlier = await js(`return document.querySelector('main table')?.innerText || ''`);
  check('E2E-DD.4', 'no endpoint was added by the search itself; Earlier searches lists it as Done with 3 names',
    after.endpoints === 0 && /journey\.invalid/.test(earlier) && /Done/.test(earlier) && /\b3\b/.test(earlier), JSON.stringify({ after, earlier }));

  // E2E-DD.5: at phone width the result does not scroll sideways.
  await go(`#/discover/${run?.discovery?.id}`);
  await viewport(390, 844, true);
  await sleep(900);
  const narrow = await js(`return document.documentElement.scrollWidth <= window.innerWidth + 1`);
  await shot('discover-result-390');
  await viewport(1440, 900, false);
  check('E2E-DD.5', 'the result page fits a 390px screen without sideways scrolling', narrow === true, String(narrow));
}
