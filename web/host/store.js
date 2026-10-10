// Browser storage for the client: a key/value store on IndexedDB, with localStorage as the fallback where
// IndexedDB is unavailable (private windows in some browsers). The identity, the contact list, the engine's
// first-contact state and the settings live here. Nothing in this file is normative.
//
// Spec: none (infrastructure).

const DB = 'dsip', STORE = 'kv';

function openDb() {
  return new Promise((resolve, reject) => {
    if (!('indexedDB' in globalThis)) return resolve(null);
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => resolve(null);
    req.onblocked = () => reject(new Error('storage blocked'));
  });
}

let dbPromise = null;
const db = () => (dbPromise ??= openDb());

function tx(mode, fn) {
  return db().then((d) => {
    if (!d) return null;
    return new Promise((resolve, reject) => {
      const t = d.transaction(STORE, mode);
      const r = fn(t.objectStore(STORE));
      t.oncomplete = () => resolve(r.result);
      t.onerror = () => reject(t.error);
    });
  });
}

export const store = {
  async get(key) {
    try {
      const v = await tx('readonly', (s) => s.get(key));
      if (v !== undefined && v !== null) return v;
    } catch { /* fall through */ }
    try { const raw = localStorage.getItem(`dsip.${key}`); return raw === null ? undefined : JSON.parse(raw); } catch { return undefined; }
  },
  async set(key, value) {
    try { const ok = await tx('readwrite', (s) => s.put(value, key)); if (ok !== null) return; } catch { /* fall through */ }
    try { localStorage.setItem(`dsip.${key}`, JSON.stringify(value)); } catch { /* storage unavailable: the session is ephemeral */ }
  },
  async del(key) {
    try { await tx('readwrite', (s) => s.delete(key)); } catch { /* ignore */ }
    try { localStorage.removeItem(`dsip.${key}`); } catch { /* ignore */ }
  },
};
