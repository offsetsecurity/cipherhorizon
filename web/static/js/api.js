// The API client. Every mutating call carries the header the server requires to
// refuse cross-site forgery, and a bearer token is sent when one was entered.

const TOKEN_KEY = 'cipherhorizon-token';

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

async function request(method, path, body, raw, contentType) {
  const headers = {};
  const t = token();
  if (t) headers['Authorization'] = `Bearer ${t}`;
  let payload;
  if (method !== 'GET') headers['X-Requested-With'] = 'cipherhorizon';
  if (body !== undefined && body !== null) {
    if (typeof body === 'string') {
      payload = body;
    } else {
      payload = JSON.stringify(body);
    }
    headers['Content-Type'] = contentType || 'application/json';
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
  inventory: (kind, params = {}) => request('GET', `/api/v1/inventory?${new URLSearchParams({ kind, ...params })}`),
  inventorySummary: () => request('GET', '/api/v1/inventory/summary'),
  inventoryDashboard: () => request('GET', '/api/v1/inventory/dashboard'),
  scanCBOM: (scanId, spec = '1.7') => request('GET', `/api/v1/scans/${scanId}/cbom?spec=${spec}`),
  scans: (query = '') => request('GET', `/api/v1/scans${query}`),
  scan: (id) => request('GET', `/api/v1/scans/${id}`),
  cancelScan: (id) => request('POST', `/api/v1/scans/${id}/cancel`),
  report: (id) => request('GET', `/api/v1/scans/${id}/report`),
  evaluation: (id) => request('GET', `/api/v1/scans/${id}/evaluation`),
  reevaluate: (id) => request('POST', `/api/v1/scans/${id}/reevaluate`),

  history: (id) => request('GET', `/api/v1/assets/${id}/history`),
  diff: (id, from, to) => request('GET', `/api/v1/assets/${id}/diff${from && to ? `?from=${from}&to=${to}` : ''}`),

  hosts: () => request('GET', '/api/v1/hosts'),
  host: (id) => request('GET', `/api/v1/hosts/${id}`),
  // A CBOM (JSON) or a facts file written by an inventory script (plain text).
  ingest: (text, name) => request('POST', `/api/v1/hosts/ingest${name ? `?name=${encodeURIComponent(name)}` : ''}`, text, false,
    text.replace(/^\uFEFF/, '').startsWith('cipherhorizon-machine-facts\t') ? 'text/plain' : 'application/json'),
  hostCBOM: (hostId, snapId) => request('GET', `/api/v1/hosts/${hostId}/snapshots/${snapId}/cbom`),
  inventoryScripts: () => request('GET', '/api/v1/collector/scripts'),
  inventorySignatures: () => request('GET', '/api/v1/collector/signatures'),
  inventoryScript: (name) => request('GET', `/api/v1/collector/scripts/${encodeURIComponent(name)}`, null, true).then((r) => r.text()),

  collectorBinaries: () => request('GET', '/api/v1/collector/binaries'),

  assetFindings: (assetId) => request('GET', `/api/v1/assets/${assetId}/findings`),
  fleetFindings: (query = '') => request('GET', `/api/v1/findings${query}`),
  setFindingStatus: (assetId, key, status, note) =>
    request('PUT', `/api/v1/assets/${assetId}/findings/${encodeURIComponent(key)}/status`, { status, note: note || '' }),
  clearFindingStatus: (assetId, key) => request('DELETE', `/api/v1/assets/${assetId}/findings/${encodeURIComponent(key)}/status`),

  linkAsset: (assetId, otherId) => request('PUT', `/api/v1/assets/${assetId}/links/${otherId}`),
  unlinkAsset: (assetId, otherId) => request('DELETE', `/api/v1/assets/${assetId}/links/${otherId}`),

  // The estate: systems, ranking, certificates, imports and correlation.
  estate: () => request('GET', '/api/v1/estate'),
  systems: () => request('GET', '/api/v1/systems'),
  system: (id) => request('GET', `/api/v1/systems/${id}`),
  patchSystem: (id, patch, reason) => request('PATCH', `/api/v1/systems/${id}${reason ? `?reason=${encodeURIComponent(reason)}` : ''}`, patch),
  systemAudit: (id) => request('GET', `/api/v1/systems/${id}/audit`),
  trustAnchors: (id) => request('GET', `/api/v1/systems/${id}/trust-anchors`),
  addTrustAnchors: (id, pem) => request('POST', `/api/v1/systems/${id}/trust-anchors`, { pem }),
  removeTrustAnchor: (id, fp) => request('DELETE', `/api/v1/systems/${id}/trust-anchors/${encodeURIComponent(fp)}`),
  serverTrustAnchors: () => request('GET', '/api/v1/trust-anchors'),
  referenceData: () => request('GET', '/api/v1/reference-data'),
  systemCertificates: (id) => request('GET', `/api/v1/systems/${id}/certificates`),
  systemLinks: (id) => request('GET', `/api/v1/systems/${id}/links`),
  systemObservations: (id) => request('GET', `/api/v1/systems/${id}/observations?current=1`),
  certificates: (query = '') => request('GET', `/api/v1/certificates${query}`),
  certificate: (fp) => request('GET', `/api/v1/certificates/${fp}`),
  links: (state = '') => request('GET', `/api/v1/links${state ? `?state=${state}` : ''}`),
  confirmLink: (id, reason) => request('POST', `/api/v1/links/${id}/confirm${reason ? `?reason=${encodeURIComponent(reason)}` : ''}`),
  rejectLink: (id, reason) => request('POST', `/api/v1/links/${id}/reject${reason ? `?reason=${encodeURIComponent(reason)}` : ''}`),
  imports: () => request('GET', '/api/v1/imports'),
  importDocument: (text, target) => request('POST', `/api/v1/imports?${target}`, text),
  withdrawImport: (id, reason) => request('POST', `/api/v1/imports/${id}/withdraw${reason ? `?reason=${encodeURIComponent(reason)}` : ''}`),

  // Downloads need the token too, so they are fetched and saved rather than linked.
  async download(path, filename) {
    const res = await request('GET', path, null, true);
    saveBlob(await res.blob(), filename);
  },

  // A client-side export of data already held in the page (no round trip):
  // used for report formats this product assembles in the browser (CSV rows,
  // a combined JSON bundle) rather than ones the server serves as a file.
  downloadBlob(filename, content, mime) {
    saveBlob(new Blob([content], { type: mime }), filename);
  },
};

function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
