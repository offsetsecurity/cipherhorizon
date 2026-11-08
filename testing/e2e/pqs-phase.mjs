// Post-quantum signatures in TLS (STRATEGY-002 C1; PRD-008 WP-A), through the browser on demo-targets:
// 9458 serves only an ML-DSA-65 certificate and picks it before answering (as OpenSSL does); 9459
// serves ECDSA and ML-DSA-65 certificates. Both have hybrid key exchange: the first is L4 (the
// post-quantum certificate is what a client gets), the second L3 with post-quantum authentication
// available (current clients get the ECDSA certificate).

export async function pqsPhase({ check, js, go, sleep, shot }) {
  const add = await js(`return fetch('/api/v1/assets/bulk', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'cipherhorizon' },
    body: JSON.stringify({ text: '127.0.0.1:9458\\n127.0.0.1:9459' }) }).then((r) => r.json())`);
  const ids = (add.results || []).map((r) => r.asset && r.asset.id).filter(Boolean);
  for (const id of ids) await js(`await fetch('/api/v1/assets/${id}/scan', { method: 'POST', headers: { 'X-Requested-With': 'cipherhorizon' } })`);
  const done = [];
  for (const id of ids) {
    let a = null;
    for (let i = 0; i < 160 && !(a && (a.lastDone || a.latest?.status === 'failed')); i++) {
      await sleep(500);
      a = await js(`return (await fetch('/api/v1/assets/${id}')).json()`);
    }
    done.push(a);
  }
  await go(`#/endpoints/${ids[1]}?tab=configuration`);
  await sleep(1500);
  const text = await js(`return document.querySelector('main').innerText`);
  const pq = await js(`return [...document.querySelectorAll('#sec-key-exchange .gchip-pq')].map((c) => c.textContent + ' ' + (c.querySelector('svg.pqg-safe') ? 'safe' : ''))`);
  check('E2E-PQS.1', 'the ML-DSA-only server is L4, the dual-certificate server L3 (post-quantum authentication available, not presented), and Configuration lists mldsa65 as accepted',
    done.length === 2 && done[0]?.lastDone?.readinessLevel === 4 && done[1]?.lastDone?.readinessLevel === 3 &&
    /Signature schemes, TLS 1\.3/.test(text) && pq.some((c) => /mldsa65/.test(c) && /ML-DSA-65/.test(c)),
    JSON.stringify(done.map((a) => [a?.port, a?.lastDone?.readinessLevel, a?.latest?.error])));
  await shot('tls-signature-schemes');
}
