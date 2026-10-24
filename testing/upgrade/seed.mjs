// Seeds a CipherHorizon server with the kinds of data a real install holds, through the HTTP API
// every release since 0.1.0 serves. make-fixture.sh runs it against a *released* version so the
// database it leaves is exactly what that release writes (PRD-016 U-02).
//
//   node testing/upgrade/seed.mjs --base http://127.0.0.1:18090 --token T --demo-base 19440 --cbom host.cbom.json
//
// Every step must succeed: a fixture missing a kind of data would test less than it claims.

import { readFileSync } from "node:fs";

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith("--") ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
);
const base = args.base;
const token = args.token;
const demo = Number(args["demo-base"] || 19440);
if (!base || !token || !args.cbom) {
  console.error("usage: seed.mjs --base URL --token TOKEN --demo-base PORT --cbom FILE");
  process.exit(2);
}

async function api(method, path, body, type = "application/json") {
  const res = await fetch(base + path, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "X-Requested-With": "cipherhorizon",
      ...(body !== undefined ? { "Content-Type": type } : {}),
    },
    body: body === undefined ? undefined : type === "application/json" ? JSON.stringify(body) : body,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${text.slice(0, 300)}`);
  return text ? JSON.parse(text) : null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const at = (n) => `127.0.0.1:${demo + n}`;

// What a real estate looks like: a range of TLS quality, a post-quantum certificate, SSH, STARTTLS,
// and an endpoint that never answers (a failed scan).
const targets = [
  { target: at(0), name: "modern-hybrid", tags: ["prod", "web"], notes: "fixture: hybrid PQ key exchange" },
  { target: at(1), name: "classical-tls13", tags: ["prod"] },
  { target: at(2), name: "legacy-tls12", tags: ["legacy"] },
  { target: at(3), name: "terrible-legacy", tags: ["legacy"], notes: "fixture: <b>markup</b> stays text" },
  { target: at(4), name: "dead-port" },
  { target: at(18), name: "mldsa-only", tags: ["pq"] },
  { target: `ssh://${at(20)}`, name: "ssh-modern", tags: ["ssh"] },
  { target: `smtp://${at(11)}`, name: "mail-starttls", tags: ["mail"] },
];

async function scanAndWait(id) {
  const sc = await api("POST", `/api/v1/assets/${id}/scan`);
  const scanId = sc?.id ?? sc?.scan?.id;
  if (!scanId) throw new Error(`scan of asset ${id}: no scan id in ${JSON.stringify(sc).slice(0, 200)}`);
  for (let i = 0; i < 240; i++) {
    const s = await api("GET", `/api/v1/scans/${scanId}`);
    const status = s?.status ?? s?.scan?.status;
    if (["done", "failed", "canceled"].includes(status)) return status;
    await sleep(500);
  }
  throw new Error(`scan ${scanId} did not finish`);
}

const ids = {};
for (const t of targets) {
  const a = await api("POST", "/api/v1/assets", t);
  ids[t.name] = a.id ?? a.asset?.id;
  if (!ids[t.name]) throw new Error(`asset ${t.name}: no id`);
}
// Scan each twice, so there is history (and a diff) to keep.
for (const round of [1, 2]) {
  for (const t of targets) {
    const status = await scanAndWait(ids[t.name]);
    console.log(`round ${round}: ${t.name} -> ${status}`);
  }
}

// A triage decision on a real finding.
const findings = await api("GET", `/api/v1/assets/${ids["legacy-tls12"]}/findings`);
const list = Array.isArray(findings) ? findings : findings?.findings ?? [];
const key = list.map((f) => f.key).find(Boolean);
if (!key) throw new Error("legacy-tls12 has no finding to triage");
await api("PUT", `/api/v1/assets/${ids["legacy-tls12"]}/findings/${encodeURIComponent(key)}/status`, {
  status: "accepted-risk",
  note: "fixture: decommissioning in Q3",
});

// A link between two endpoints (the same service behind two names).
await api("PUT", `/api/v1/assets/${ids["modern-hybrid"]}/links/${ids["classical-tls13"]}`);

// A host inventory, as the collector uploads it.
await api("POST", "/api/v1/hosts/ingest", JSON.parse(readFileSync(args.cbom, "utf8")));

const summary = await api("GET", "/api/v1/summary");
console.log("seeded:", JSON.stringify(summary).slice(0, 300));
