// PRD-012 (the certificate viewer), driven through the browser on the other phases' data: every
// chain node opens the certificate's page and Back returns; the page has every section in order and
// agrees with the API; its PEM is the certificate; a hostile certificate stays text; and the page
// works on a phone and with the keyboard.

const words = (st) => (!st ? 'not rated' : st.status === 'rated' ? `${st.bits} bits` : st.status === 'disallowed' ? `${st.bits} bits, disallowed`
  : st.status === 'broken' ? 'broken' : 'not rated');

export async function x509Phase({ check, js, go, sleep, shot, viewport }) {
  await viewport(1440, 900, false);
  const endpoints = await js(`return (await (await fetch('/api/v1/assets?kind=endpoint')).json()).filter((a) => a.protocol !== 'ssh' && a.lastDone)`);
  const hostile = endpoints.find((a) => a.port === 9450);
  const target = hostile || endpoints[0];

  // E2E-XV-1: every node of Chain as served is a link to the certificate's page for that scan;
  // the page names the scan and Back returns to the chain.
  await go(`#/endpoints/${target.id}?tab=configuration`);
  await sleep(1500);
  const nodes = await js(`return [...document.querySelectorAll('.servednode .servedcn a')].map((a) => a.getAttribute('href'))`);
  const chainLen = await js(`return document.querySelectorAll('.servednode:not(.missing)').length`);
  const firstHref = nodes[0];
  await js(`document.querySelector('.servednode .servedcn a').click(); return true`);
  await sleep(1600);
  const at = await js(`return { hash: location.hash, served: document.querySelector('.served-by')?.textContent || '' }`);
  await js(`history.back(); return true`);
  await sleep(1500);
  const back = await js(`return { hash: location.hash, chain: !!document.querySelector('.servednode') }`);
  check('E2E-XV-1', 'every certificate in Chain as served opens its own page for that scan, which names the endpoint and its place in the chain; Back returns to the chain',
    nodes.length > 0 && nodes.length === chainLen && nodes.every((h) => new RegExp(`^#/certificates/[0-9a-f]{64}\\?scan=${target.lastDone.id}$`).test(h))
      && at.hash === firstHref && /Served by .+certificate 1 of \d+ in the chain/.test(at.served) && back.chain && /^#\/endpoints\//.test(back.hash),
    JSON.stringify({ nodes: nodes.length, chainLen, at, back }).slice(0, 400));

  // E2E-XV-2: the page's sections, in ENH-003 §3.2's order, agree with the API.
  const fp = firstHref.slice('#/certificates/'.length).split('?')[0];
  const api = await js(`return (await fetch('/api/v1/certificates/${fp}/x509?scan=${target.lastDone.id}')).json()`);
  await go(firstHref);
  await sleep(1600);
  const page = await js(`const h2 = [...document.querySelectorAll('#main h2')].map((x) => x.textContent);
    const facts = Object.fromEntries([...document.querySelectorAll('#main dl.facts > div')].map((d) => [d.querySelector('dt').textContent, d.querySelector('dd').textContent]));
    return { h2, extRows: document.querySelectorAll('.x509-ext tbody tr').length, key: facts['Classical strength'] || '', serial: facts['Serial number'] || '', sha256: facts['SHA-256'] || '' }`);
  const order = ['Identity', 'Names', 'Public key', 'Signature', `Extensions (${api.x509.extensions.length})`, 'Fingerprints', 'The certificate (PEM)'];
  check('E2E-XV-2', 'the certificate page has Identity, Names, Public key, Signature, every Extension, Fingerprints and the PEM, in that order, agreeing with the API',
    api.der && order.every((t, i) => page.h2[i] === t) && page.extRows === api.x509.extensions.length && page.key.startsWith(words(api.x509.publicKey.strength))
      && page.serial.includes(api.x509.serial) && page.sha256.includes(api.x509.sha256),
    JSON.stringify({ h2: page.h2, extRows: page.extRows, want: api.x509 && api.x509.extensions.length, key: page.key.slice(0, 40) }));
  await shot('x509-page');

  // E2E-XV-3: the PEM on the page is this certificate, and it can be downloaded.
  const pem = await js(`const text = document.querySelector('pre.pem')?.textContent || '';
    const b64 = text.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\\s+/g, '');
    const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const sum = [...new Uint8Array(await crypto.subtle.digest('SHA-256', der))].map((b) => b.toString(16).padStart(2, '0')).join('');
    return { sum, buttons: [...document.querySelectorAll('#main button')].map((b) => b.textContent).filter((t) => /PEM|\\.pem/.test(t)) }`);
  check('E2E-XV-3', 'the PEM shown is the certificate (its SHA-256 is the fingerprint), with Copy PEM and Download .pem',
    pem.sum === fp && pem.buttons.includes('Copy PEM') && pem.buttons.includes('Download .pem'), JSON.stringify(pem));

  // E2E-XV-4: a certificate full of markup (the hostile demo target) renders as text.
  if (hostile) {
    await js('window.__xss = undefined; return true');
    await go(firstHref);
    await sleep(1600);
  }
  const inert = await js(`return { fired: window.__xss ?? null, injected: document.querySelectorAll('#main img, #main script, #main iframe, #main [onerror], #main svg[onload]').length,
    links: [...document.querySelectorAll('#main a')].map((a) => a.getAttribute('href')).filter((h) => /^javascript:/i.test(h || '')).length,
    shown: /<img src=x onerror=/.test(document.querySelector('#main').textContent) }`);
  check('E2E-XV-4', 'a certificate whose subject, names and URLs are markup renders them as text: nothing runs, nothing is injected, no javascript: link',
    !!hostile && inert.fired === null && inert.injected === 0 && inert.links === 0 && inert.shown, JSON.stringify({ hostile: !!hostile, ...inert }));

  // E2E-XV-5: on a phone the page does not scroll sideways, and every control is reachable by Tab.
  await viewport(375, 812, false, true);
  await go(firstHref);
  await sleep(1600);
  const phone = await js(`return { overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    unreachable: [...document.querySelectorAll('#main a[href], #main button, #main summary, #main pre.pem')].filter((el) => el.tabIndex < 0).length,
    pemFocusable: document.querySelector('pre.pem')?.tabIndex === 0 }`);
  await shot('x509-phone');
  await viewport(1440, 900, false);
  check('E2E-XV-5', 'the certificate page fits a 375 px phone with no sideways scroll, and every link, button and the PEM block is reachable by Tab',
    phone.overflow <= 0 && phone.unreachable === 0 && phone.pemFocusable, JSON.stringify(phone));
}
