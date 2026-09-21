// The API client. Every mutating call carries the header the server requires to
// refuse cross-site forgery, and a bearer token is sent when one was entered.

const TOKEN_KEY = 'cbom-scan-token';

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

let onAuthRequired = null;
export function setAuthHandler(fn) { onAuthRequired = fn; }

export function setToken(t) {
  try { sessionStorage.setItem(TOKEN_KEY, t); } catch { /* storage may be unavailable */ }
}

function token() {
  try { return sessionStorage.getItem(TOKEN_KEY) || ''; } catch { return ''; }
}

async function request(method, path, body, raw) {
  const headers = {};
  const t = token();
  if (t) headers['Authorization'] = `Bearer ${t}`;
  let payload;
  if (method !== 'GET') headers['X-Requested-With'] = 'cbom-scan';
  if (body !== undefined && body !== null) {
    if (typeof body === 'string') {
      payload = body;
    } else {
      payload = JSON.stringify(body);
    }
    headers['Content-Type'] = 'application/json';
  }
  let res;
  try {
    res = await fetch(path, { method, headers, body: payload });
  } catch {
    throw new ApiError(0, 'Cannot reach the server. Is it still running?');
  }
  if (res.status === 401) {
    if (onAuthRequired) onAuthRequired();
    throw new ApiError(401, 'A valid access token is required.');
  }
  if (raw) {
    if (!res.ok) throw new ApiError(res.status, await errorText(res));
    return res;
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, (data && data.error) || `Request failed (${res.status})`);
  return data;
}

async function errorText(res) {
  const d = await res.json().catch(() => null);
  return (d && d.error) || `Request failed (${res.status})`;
}

export const api = {
  about: () => request('GET', '/api/v1/about'),
  summary: (days = 14) => request('GET', `/api/v1/summary?days=${days}`),

  assets: () => request('GET', '/api/v1/assets?kind=tls-endpoint'),
  asset: (id) => request('GET', `/api/v1/assets/${id}`),
  addAsset: (target, name, tags) => request('POST', '/api/v1/assets', { target, name: name || '', tags: tags || [] }),
  addBulk: (text, tags) => request('POST', '/api/v1/assets/bulk', { text, tags: tags || [] }),
  patchAsset: (id, patch) => request('PATCH', `/api/v1/assets/${id}`, patch),
  deleteAsset: (id) => request('DELETE', `/api/v1/assets/${id}`),

  scanAsset: (id) => request('POST', `/api/v1/assets/${id}/scan`),
  scanMany: (body) => request('POST', '/api/v1/scans', body),
  scans: (query = '') => request('GET', `/api/v1/scans${query}`),
  scan: (id) => request('GET', `/api/v1/scans/${id}`),
  cancelScan: (id) => request('POST', `/api/v1/scans/${id}/cancel`),
  report: (id) => request('GET', `/api/v1/scans/${id}/report`),
  evaluation: (id) => request('GET', `/api/v1/scans/${id}/evaluation`),

  history: (id) => request('GET', `/api/v1/assets/${id}/history`),
  diff: (id, from, to) => request('GET', `/api/v1/assets/${id}/diff${from && to ? `?from=${from}&to=${to}` : ''}`),

  hosts: () => request('GET', '/api/v1/hosts'),
  host: (id) => request('GET', `/api/v1/hosts/${id}`),
  ingest: (json, name) => request('POST', `/api/v1/hosts/ingest${name ? `?name=${encodeURIComponent(name)}` : ''}`, json),

  // Downloads need the token too, so they are fetched and saved rather than linked.
  async download(path, filename) {
    const res = await request('GET', path, null, true);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  },
};
