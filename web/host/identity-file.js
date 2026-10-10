// The identity file: the person's identity key, encrypted with a passphrase. The export is the only copy of the
// identity key outside the browser; importing it on another browser enrols that browser as a device of the same
// identity: the app makes a fresh device key there and the identity key signs its delegation (§7.4), no server
// involved. The exporting device's own key travels in the file but is never reused by an importer.
//
// Format (version 1): JSON `{"dsip-identity": 1, "identity": <did>, "kdf": {"name": "PBKDF2", "hash": "SHA-256",
// "iterations", "salt"}, "cipher": {"name": "AES-GCM", "iv"}, "ciphertext"}`, binary fields base64; the plaintext
// is the identity JSON `create_identity` returned (seeds included), plus `devices` (the exporter's device list, what
// it knows) and `revoked` (the revocations it issued). Spec: none (infrastructure); the client plan §5 and spec-gap
// "identity export" propose whether this becomes a specified format.

const ITERATIONS = 600_000;
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function deriveKey(passphrase, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** Encrypt an identity (the JSON object from `create_identity`) under `passphrase`; returns the file text. */
export async function exportIdentity(identity, passphrase) {
  if (!passphrase || passphrase.length < 8) throw new Error('a passphrase of at least 8 characters is required');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, ITERATIONS);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(identity)));
  return JSON.stringify({
    'dsip-identity': 1, identity: identity.identity,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: ITERATIONS, salt: b64(salt) },
    cipher: { name: 'AES-GCM', iv: b64(iv) }, ciphertext: b64(ciphertext),
  }, null, 1);
}

/** Decrypt an identity file; returns the identity JSON object, or throws (wrong passphrase, not a file). */
export async function importIdentity(text, passphrase) {
  let f;
  try { f = JSON.parse(text); } catch { throw new Error('not an identity file'); }
  if (f['dsip-identity'] !== 1 || f.kdf?.name !== 'PBKDF2' || f.cipher?.name !== 'AES-GCM') throw new Error('not an identity file (version 1)');
  const key = await deriveKey(passphrase, unb64(f.kdf.salt), f.kdf.iterations);
  let plain;
  try { plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(f.cipher.iv) }, key, unb64(f.ciphertext)); }
  catch { throw new Error('wrong passphrase, or the file is damaged'); }
  const id = JSON.parse(dec.decode(plain));
  if (id.identity !== f.identity || !id.controller_seed_hex) throw new Error('the file does not hold an identity');
  return id;
}
