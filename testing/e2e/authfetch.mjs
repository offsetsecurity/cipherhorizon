// The journey's own API calls (setting up fixtures, reading results) run outside the browser, so
// they cannot use its session cookie. They use the automation token the test server was started
// with (ADR-0018), passed as E2E_TOKEN. The browser itself signs in through the UI.
const TOKEN = process.env.E2E_TOKEN || '';

export function authFetch(url, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (TOKEN && !headers.Authorization) headers.Authorization = `Bearer ${TOKEN}`;
  return globalThis.fetch(url, { ...opts, headers });
}
