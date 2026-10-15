// DSIP reference client — the screens. Everything normative (verification, the §12 engine, payload building,
// first-contact state) runs inside dsip_wasm; this file owns the views and the one current call, and drives the
// host layer (relay socket, WebRTC, storage). No signaling decision is made here: a screen changes only when the
// engine emits.
//
// Spec: §12 (engine states shown as they are), §12.12 (ICE candidates in signed `info`, ACTIVE-only), §14.1 (no
// media before a signed answer), §14.4 (screening), §18.1 (the verification basis, never a badge), §18.2 (display
// names are claims), §19.4 (first contact), B§ (SDP in `transports[].sdp`), G§5/G§7 (PSTN caller line, downgrade),
// N§4 (a caller's bound number, checked by `check_claim`), N§4.1 (`tel:` through a gateway as `destination`), N§5
// (a number that moved), N§6 (number lookup on the nodes in Settings), §8.1/§8.3 and DHT Hints Profile §10 (a
// signed reachability hint published on the nodes and looked up before a call: hint-sourced, never authoritative;
// a call to someone bound elsewhere goes through the relay their hint names), Messaging Profile M§4.2 (the mailbox a
// did:key identity names in its hint, and the peer's found the same way), M§4.3 (bound with a verified hello), M§7.2
// and M§8.1 (text in a direct conversation; every decision inside `Messenger`, spec-gap 44: its MLS and delivery state
// saved together after each step).

import init, { create_identity, revocation_frame, rehome, did_document, check_claim, identity_change, tn_select, hint_frame, hint_select, mailbox_select, voicemail_offer, redelegate, Endpoint, Messenger, verification_basis, tel_caller_line, downgrade_summary } from './pkg/dsip_wasm.js';
import { store } from './host/store.js';
import { Engine } from './host/engine.js';
import { Relay } from './host/relay.js';
import { Media } from './host/media.js';
import { exportIdentity, importIdentity } from './host/identity-file.js';

const $ = (id) => document.getElementById(id);
const now = () => Date.now() / 1000;
// `?as=` namespaces storage so two tabs on one origin can be two people (a convenience for trying it alone).
const slot = new URLSearchParams(location.search).get('as') || '';
const key = (k) => (slot ? `${slot}.${k}` : k);
const short = (d) => (d && d.length > 32 ? d.slice(0, 20) + '…' + d.slice(-8) : d || '');

let identity = null, engine = null, relay = null, settings = {}, contacts = [];
let call = null;      // {sid, role, peer, media, offer, pendingUpdate, screening}
let relayInfo = null;
let purposes = {};    // introduction id → {purpose, basis}: what a request shows (the engine keeps only the ids)
let links = [];       // contact links issued here: {token, url, created}
let onBound = null;   // one action deferred until the relay is bound (a contact link opened before connecting)
let devices = [];     // {device, enrolled?}: this identity's devices as this browser knows them (no registry for did:key)
let revoked = [];     // {device, reason, at, frame}: revocations this identity issued here (§7.4)
let documents = {};   // did → DID document held here (§8.1; the CLI's --did-document): did:web signers verify against them
let served = {};      // the operator's defaults, `config.json` beside this page (spec-gap 114); a setting left empty takes them
const callRelays = new Map();   // session → a Relay opened to the peer's own relay for that call (their hint named it, §8.1)
let ice = null;       // {servers, until}: ICE servers in effect, from Settings, the operator, or the relay's /turn (short-lived)
let hintTimer = null; // re-signs the published reachability hint at ⅔ of its life
let hintSeq = 0;      // the last `seq` this browser published (§8.3: newer wins; a re-sign within the same second must still be newer)
let messenger = null; // the wasm messaging device (stage 6), when a mailbox is configured
let mailboxConn = null, mailboxInfo = null;   // the Relay to this identity's mailbox, and its verified hello
let activeConv = null;                        // the group id open on the Messages screen
const waiters = [];                           // {pred, resolve}: one-shot waits for a Messenger emission on the mailbox connection
let messagingTick = null;                     // advances the receipts machines (M§10.3: a held read goes out when 5 s pass)
const lastRead = {};                          // group → the content id this screen last reported read (M§10.3)
let reconciling = null;                       // the device reconciliation in progress (M§12.3), one at a time
const media = {};                             // content id → {url, state: 'fetching'|'ready'|'failed', attempt, why}: blobs fetched and opened (M§8.4)
let recorder = null;                          // {rec, chunks, started, stream} while a voice message is being recorded
const VOICEMAIL_MAX_S = 180;                  // what this client's owner accepts as voicemail (M§4.2 `voicemail.max_duration_s`)
const EXTERNAL_JOIN_WAIT_S = 30;              // Impl: how long a device that knows of siblings waits to be added (M§12.3) before joining by external commit; M§6.8 leaves it to the device (v0.13, spec-gap 120)
let externalJoinTimer = null;
let pendingVoicemail = null;                  // {peer, session, max_s}: a voicemail offered after an unanswered call (M§13.2)
let lastVoice = null;                         // what the last recording became: {plain_size, sha256, size, content_type, duration_ms} (for tests)
const HINT_TTL_S = 3600;   // the profile's maximum (§12.9, spec-gap 96)
// A setting of null says "none", overriding the operator's default (typed as `none` in Settings).
const setting = (k) => (settings[k] === null ? undefined : settings[k] !== undefined && settings[k] !== '' && !(Array.isArray(settings[k]) && !settings[k].length) ? settings[k] : served[k]);
const noneable = (text, list) => (/^none$/i.test(text.trim()) ? null : list ? text.split(/[\s,]+/).filter(Boolean) : text.trim() || undefined);
const nodesInEffect = () => setting('nodes') || [];
const publishHint = () => (setting('publish_hint') ?? true) && nodesInEffect().length > 0;
const payloadOf = (frame) => { try { return JSON.parse(atob(JSON.parse(frame).payload.replace(/-/g, '+').replace(/_/g, '/'))); } catch { return {}; } };

// ---------------------------------------------------------------- log

function log(line, sec = '') {
  const el = $('log');
  el.textContent += `${new Date().toLocaleTimeString()}  ${line}${sec ? '   ' + sec : ''}\n`;
  el.scrollTop = el.scrollHeight;
}

// ---------------------------------------------------------------- views

function show(view) {
  for (const v of document.querySelectorAll('.view:not(.overlay)')) v.classList.toggle('hidden', v.id !== `view-${view}`);
}

function nameOf(did) { return contacts.find((c) => c.did === did)?.name || ''; }

function renderHeader() {
  $('me-name').textContent = identity.display_name || '(no name)';
  $('me-did').textContent = identity.identity;
}

// The lists are rebuilt only when what they show changed: they are asked to render on many events, and a button
// replaced under a click would swallow it.
let shownContacts = null, shownRequests = null;
function renderContacts() {
  const file = JSON.parse(engine.contactsFile());     // grants by id → {identity, scope, valid_until}
  const rows = contacts.map((c) => {
    const held = Object.values(file.grants_held || {}).some((g) => g.identity === c.did);
    const issued = Object.values(file.grants_issued || {}).some((g) => g.identity === c.did);
    const pending = Object.values(file.pending_sent || {}).includes(c.did);
    const asked = Object.values(file.requests || {}).some(([who]) => who === c.did);
    const status = held && issued ? 'mutual grant' : held ? 'they granted you' : issued ? 'you granted them'
      : asked ? 'wants to connect: see Requests' : pending ? 'introduction sent, waiting' : 'no grant';
    return { c, status };
  });
  const key = JSON.stringify(rows.map(({ c, status }) => [c.name, c.did, c.numbers, status]));
  if (key !== shownContacts) { shownContacts = key; renderContactRows(rows); }
  renderRequests();
}

function renderContactRows(rows) {
  const ul = $('contact-list');
  ul.innerHTML = '';
  if (!rows.length) ul.innerHTML = '<li class="muted small">no contacts yet: paste a DID above</li>';
  for (const { c, status } of rows) {
    const li = document.createElement('li');
    li.innerHTML = `<span class="name"></span><code class="did"></code><span class="muted small num"></span><span class="status">${status}</span>`;
    li.querySelector('.name').textContent = c.name || '(unnamed)';
    li.querySelector('.did').textContent = c.did;
    li.querySelector('.num').textContent = (c.numbers || []).join(' ');
    const b = (text, cls, fn) => { const x = document.createElement('button'); x.textContent = text; if (cls) x.className = cls; x.onclick = fn; return x; };
    li.append(b('Call', 'primary', () => placeCall(c.did, false)), b('Video', '', () => placeCall(c.did, true)),
      b('Message', '', () => messagePeer(c.did)), b('Introduce', '', () => introduce(c.did)), b('Remove', 'ghost', () => removeContact(c.did)));
    ul.append(li);
  }
}

function renderRequests() {
  const reqs = engine.requests();
  const key = JSON.stringify(reqs.map(([id, who]) => [id, who, nameOf(who), purposes[id]?.purpose, purposes[id]?.basis]));
  if (key === shownRequests) return;
  shownRequests = key;
  const rl = $('request-list');
  rl.innerHTML = reqs.length ? '' : '<li class="muted small">none</li>';
  for (const [id, who] of reqs) {
    const li = document.createElement('li');
    li.innerHTML = `<div class="request"><span class="name"></span> <code class="did"></code><div class="small purpose"></div><div class="small basis"></div></div>`;
    li.querySelector('.name').textContent = nameOf(who) || 'someone';
    li.querySelector('.did').textContent = who;
    li.querySelector('.purpose').textContent = purposes[id]?.purpose ? `“${purposes[id].purpose}”  (a claim, §18.2)` : '(no purpose given)';
    li.querySelector('.basis').textContent = purposes[id]?.basis || '';
    const g = document.createElement('button'); g.textContent = 'Grant'; g.className = 'primary';
    g.onclick = () => engine.local({ local: 'grant', introduction: id, id: engine.newId(), scope: ['dsip.invite', 'dsip.message'], valid_until: Math.floor(now()) + 31536000 });   // §19.4; M§14.2: calls and messages
    const r = document.createElement('button'); r.textContent = 'Ignore';
    r.onclick = () => engine.local({ local: 'reject_introduction', introduction: id, reason: 'user.declined' });
    li.append(g, r);
    rl.append(li);
  }
}

function renderCall() {
  if (!call) return;
  const st = engine.state(call.sid);
  $('call-state').textContent = st || '';
  $('call-title').textContent = { INVITING: 'Calling', PROCEEDING: 'Ringing', ACTIVE: 'In call', ENDED: 'Call ended' }[st] || (call.role === 'responder' ? 'Answering' : 'Calling');
  $('btn-add-video').classList.toggle('hidden', !(st === 'ACTIVE' && !call.screening && !call.media?.localStream?.getVideoTracks().length));
  $('btn-escalate').classList.toggle('hidden', !(st === 'ACTIVE' && call.screening));
  $('btn-answer-update').classList.toggle('hidden', !call.pendingUpdate);
  $('btn-reject-update').classList.toggle('hidden', !call.pendingUpdate);
}

function renderSettings() {
  $('set-name').value = identity.display_name || '';
  $('set-did').textContent = identity.identity;
  $('set-device').textContent = identity.device;
  $('set-first-contact').checked = !!settings.first_contact_required;
  $('set-read-disclosed').checked = !!settings.read_disclosed;
  $('set-record-keeper').value = settings.record_keeper || '';
  $('record-keeper-status').textContent = settings.record_keeper ? `records go to ${nameOf(settings.record_keeper) || short(settings.record_keeper)}${messenger?.held_records() ? `; ${messenger.held_records()} held until it opens the conversation` : ''}` : 'none: no call records are sent';
  $('btn-become-keeper').disabled = !identity.controller_seed_hex || !!messenger?.is_recorder();
  $('set-relay').value = settings.relay || '';
  $('set-relay').placeholder = served.relay || `wss://${location.host}/dsip`;
  $('set-ice').value = settings.ice ? JSON.stringify(settings.ice) : '';
  if (served.ice) $('set-ice').placeholder = JSON.stringify(served.ice);
  $('set-nodes').value = settings.nodes === null ? 'none' : (settings.nodes || []).join(', ');
  $('set-nodes').placeholder = (served.nodes || []).join(', ') || 'https://node.example:8090, …';
  $('set-publish-hint').checked = publishHint();
  $('set-mailbox').value = settings.mailbox === null ? 'none' : settings.mailbox?.uri || '';
  $('set-mailbox-did').value = settings.mailbox?.did || '';
  if (served.mailbox) { $('set-mailbox').placeholder = served.mailbox.uri || ''; $('set-mailbox-did').placeholder = served.mailbox.did || ''; }
  renderNetwork();
  const web = identity.identity.startsWith('did:web:');
  $('set-did-web').value = web ? identity.identity : '';
  $('did-web-host').classList.toggle('hidden', !web);
  if (web) $('did-web-url').textContent = didWebUrl(identity.identity);
  $('set-binding').value = settings.binding || '';
  $('binding-status').textContent = bindingStatus();
  $('set-gateway').value = settings.gateway === null ? 'none' : settings.gateway || '';
  if (served.gateway) $('set-gateway').placeholder = `${served.gateway} (operator default; type none to override)`;
  $('set-tn-policy').value = settings.tn_policy ? JSON.stringify(settings.tn_policy) : '';
  renderDevices();
  renderDocuments();
}

/** What the network settings resolve to, with where each came from. */
function renderNetwork() {
  const src = (k) => (settings[k] === null ? 'yours: none' : settings[k] !== undefined && settings[k] !== '' && !(Array.isArray(settings[k]) && !settings[k].length) ? 'yours' : served[k] !== undefined ? 'operator default' : 'built-in default');
  const iceLine = settings.ice ? `${JSON.stringify(settings.ice)} (yours)` : served.ice ? `${JSON.stringify(served.ice)} (operator default)`
    : ice?.servers?.length ? `${ice.servers.map((s) => [].concat(s.urls).join(' ')).join('; ')} (short-lived credentials from the relay's /turn, until ${new Date(ice.until * 1000).toLocaleTimeString()})` : 'none: host candidates only (the relay mints no TURN credentials)';
  $('network-effective').textContent = [
    `relay: ${relayUrl()} (${src('relay')})`,
    `ICE: ${iceLine}`,
    `nodes: ${nodesInEffect().join(', ') || 'none'} (${src('nodes')})`,
    `reachability hint: ${publishHint() ? `published on the nodes, ${HINT_TTL_S} s, re-signed at ⅔` : 'not published'}`,
    `gateway: ${setting('gateway') || 'none'} (${src('gateway')})`,
    `mailbox: ${mailboxOf() ? `${mailboxOf().uri} ${mailboxOf().did}` : 'none (messaging off)'} (${src('mailbox')})`,
  ].join('\n');
}

/** The mailbox this identity uses (M§4.2): Settings, else the operator's; `{uri, did}` or null. */
function mailboxOf() {
  const m = setting('mailbox');
  return m && m.uri && m.did ? m : null;
}

/** Where a did:web document is served (§8.4): `https://<host>/.well-known/did.json`, or `/<path>/did.json`. */
function didWebUrl(did) {
  const [host, ...path] = did.slice('did:web:'.length).split(':');
  return path.length ? `https://${host.replace('%3A', ':')}/${path.join('/')}/did.json` : `https://${host.replace('%3A', ':')}/.well-known/did.json`;
}

function bindingPayload(jws) { try { return JSON.parse(atob(jws.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))); } catch { return {}; } }
function bindingNumber() { return bindingPayload(settings.binding || '').tn || ''; }

/** Our own did:web document (§7.2): the identity key, and `tel:` for the bound number (N§3.3). `null` for did:key. */
function ownDocument() {
  if (!identity.identity.startsWith('did:web:')) return null;
  return JSON.parse(did_document(JSON.stringify(identity), JSON.stringify(bindingNumber() ? [`tel:${bindingNumber()}`] : [])));
}

/** What a callee holding our document and this policy would make of our binding (N§3.4), said before any call. */
function bindingStatus() {
  if (!settings.binding) return 'no binding: your calls present no number';
  const claim = { type: 'tel', number: bindingNumber(), binding: settings.binding };
  const out = JSON.parse(check_claim(JSON.stringify(claim), identity.identity, JSON.stringify(ownDocument()), now(), JSON.stringify(settings.tn_policy || {})));
  if (out.outcome === 'attested') return `${out.line} — verifies, as a callee holding your document and this policy sees it (N§3.4)`;
  const hint = out.reason === 'not-claimed-by-did'
    ? (identity.identity.startsWith('did:web:') ? ' (your document must list the number: host the one above)' : ' (a bound number needs a did:web identity whose document lists it, N§3.3)')
    : out.reason === 'untrusted-certificate' ? ' (no anchor in the number policy covers the issuer)' : '';
  return `${out.line || 'the binding'} — would be refused: ${out.reason}${hint}`;
}

function renderDocuments() {
  const ul = $('document-list');
  const ids = Object.keys(documents);
  ul.innerHTML = ids.length ? '' : '<li class="muted small">none</li>';
  for (const id of ids) { const li = document.createElement('li'); li.innerHTML = '<code class="did"></code>'; li.querySelector('.did').textContent = id; ul.append(li); }
}

/** Hold a did:web document (§8.1): it is the authority for its DID; this browser does not fetch, the person pastes. */
async function addDocument(text) {
  let doc;
  try { doc = JSON.parse(text); } catch { return notify('a DID document is JSON'); }
  if (!doc || typeof doc.id !== 'string' || !doc.id.startsWith('did:web:')) return notify('a DID document names its did:web id');
  if (!engine.ep.add_document(JSON.stringify(doc))) return notify('that document could not be read');
  documents[doc.id] = doc;
  await store.set(key('documents'), documents);
  renderDocuments();
  log(`holding the DID document of ${doc.id}`, '§8.1');
}

/** Rehome to did:web (§7.2): the same keys under a hosted name; the delegation is re-signed under `<did>#key-1`. */
async function useDidWeb(did) {
  did = did.trim();
  if (!/^did:web:[a-z0-9.%:-]+$/i.test(did)) return alert('a did:web DID looks like did:web:alice.example (or did:web:host:path)');
  identity = JSON.parse(rehome(JSON.stringify(identity), did, now()));
  await store.set(key('identity'), identity);
  location.reload();
}

function downloadDidDocument() {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(ownDocument(), null, 2)], { type: 'application/json' }));
  a.download = 'did.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

async function saveNumbers() {
  settings.gateway = noneable($('set-gateway').value);
  try { settings.tn_policy = $('set-tn-policy').value.trim() ? JSON.parse($('set-tn-policy').value) : undefined; } catch { return alert('the number policy must be JSON'); }
  await saveSettings();
  renderSettings();
}

async function saveBinding(jws) {
  jws = jws.trim();
  if (jws && !bindingPayload(jws).tn) return alert('that is not a binding (a compact JWS whose payload names tn)');
  settings.binding = jws || undefined;
  await saveSettings();
  renderSettings();
}

function renderDevices() {
  const ul = $('device-list');
  ul.innerHTML = '';
  for (const d of devices) {
    const li = document.createElement('li');
    const mine = d.device === identity.device;
    li.innerHTML = '<code class="did"></code><span class="status"></span>';
    li.querySelector('.did').textContent = d.device;
    li.querySelector('.status').textContent = mine ? 'this browser' : d.enrolled ? `enrolled ${new Date(d.enrolled * 1000).toLocaleString()}` : 'added by DID';
    if (!mine) { const b = document.createElement('button'); b.textContent = 'Revoke'; b.className = 'ghost'; b.onclick = () => revoke(d.device); li.append(b); }
    ul.append(li);
  }
  const rl = $('revoked-list');
  rl.innerHTML = '';
  for (const r of revoked) {
    const li = document.createElement('li');
    li.innerHTML = '<code class="did"></code><span class="status"></span>';
    li.querySelector('.did').textContent = r.device;
    li.querySelector('.status').textContent = `revoked (${r.reason}) ${new Date(r.at * 1000).toLocaleString()}`;
    rl.append(li);
  }
}

function renderRelay(text, state) {
  $('relay-status').textContent = text;
  $('relay-dot').className = `dot ${state}`;
}

// ---------------------------------------------------------------- persistence

let lastPersist = Promise.resolve();
/** The engine's contact file to storage; the write in flight is kept so a caller can wait for it. */
function persist() {
  lastPersist = store.set(key('engine.contacts'), engine.contactsFile());
  return lastPersist;
}

function renderLinks() {
  const ul = $('contact-links');
  ul.innerHTML = links.length ? '' : '<li class="muted small">none yet</li>';
  const file = JSON.parse(engine.contactsFile());
  for (const l of links) {
    const li = document.createElement('li');
    li.innerHTML = '<code class="did link"></code><span class="status"></span>';
    li.querySelector('.link').textContent = l.url;
    li.querySelector('.status').textContent = Object.prototype.hasOwnProperty.call(file.tokens || {}, l.token) ? 'unused' : 'used';
    ul.append(li);
  }
}

async function newContactLink() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const token = btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  await engine.local({ local: 'issue_token', token, grant_id: engine.newId() });   // §19.4: single-use, auto-granted
  const url = `${location.origin}${location.pathname}?contact=${encodeURIComponent(identity.identity)}&token=${token}&name=${encodeURIComponent(identity.display_name || '')}`;
  links.push({ token, url, created: Math.floor(now()) });
  await store.set(key('links'), links);
  renderLinks();
  navigator.clipboard?.writeText(url).catch(() => {});
  notify('contact link made (and copied): hand it to one person');
}

async function saveContacts() { await store.set(key('contacts'), contacts); renderContacts(); }

// ---------------------------------------------------------------- engine events

async function onReceived(r) {
  const m = r.message, p = r.payload;
  log(`← ${m.type.padEnd(12)} from ${short(r.identity)}${r.display_name ? ` "${r.display_name}"` : ''}  ✓ signature · delegation · replay · schema`, '§10.2');
  if (m.type === 'introduction') {
    // what the request will show: the stated purpose (a claim) and the introducer's §18.1 basis
    purposes[m.id] = { purpose: p.purpose || '', basis: verification_basis(r.identity, JSON.stringify((p.identity && p.identity.claims) || [])) };
    await store.set(key('purposes'), purposes);
    renderContacts();   // the request is listed now, with its purpose and basis
    return;
  }
  if (m.type === 'error') log(`   error ${m.reason || ''}${p.detail ? ': ' + (typeof p.detail === 'string' ? p.detail : JSON.stringify(p.detail)) : ''}`, '§15');
  if (m.type === 'error' && m.reason === 'policy.rate-limited') {
    notify(`the relay limits introductions (§19.4): try again in ${p.retry_after ?? '?'} s`);
    return;
  }
  if (m.type === 'invite') {
    if (engine.state(m.id) !== 'OFFERED') return;   // policy refused it (first contact): no ring, no screen
    if (call && engine.state(call.sid) !== 'ENDED') {
      // Impl: one call at a time in this client; a second invite is declined as busy (§15 user.busy).
      await engine.local({ local: 'decline', session: m.id, reason: 'user.busy' });
      log(`busy: declined a second call from ${short(r.identity)}`, '§15');
      return;
    }
    call = { sid: m.id, role: 'responder', peer: r.identity, offer: p, media: null, pendingUpdate: null, screening: false };
    const claims = (p.identity && p.identity.claims) || [];
    const tel = claims.find((c) => c.type === 'tel');
    $('in-name').textContent = nameOf(r.identity) || r.display_name || '(no name)';
    $('in-did').textContent = r.identity;
    $('in-caller').textContent = tel ? '☎ ' + tel_caller_line(JSON.stringify(tel)) + ' (via gateway)' : '';
    $('in-caller').classList.toggle('hidden', !tel);
    $('in-basis').textContent = verification_basis(r.identity, JSON.stringify(claims));
    // N§4: the caller's own bound numbers, verified against the identity that signed this invite and its document;
    // N§5: a number that a stored contact lists but that now belongs to another identity is said out loud
    const numberLines = [], warnings = [];
    for (const c of claims) {
      const out = JSON.parse(check_claim(JSON.stringify(c), r.identity, JSON.stringify(documents[r.identity] ?? null), now(), JSON.stringify(setting('tn_policy') || {})));
      if (out.outcome === 'attested') {
        numberLines.push(`☎ ${out.line} (N§4)`);
        const w = identity_change(JSON.stringify(contacts), c.number, r.identity, out.attested_by ?? undefined, out.issued);
        if (w) warnings.push(`⚠ ${w} (N§5)`);
      } else if (out.outcome === 'dropped') numberLines.push(`☎ ${out.line || 'a number'} — number binding refused: ${out.reason} (N§4, §18.2)`);
    }
    $('in-numbers').textContent = numberLines.join('\n');
    $('in-tn-warning').textContent = warnings.join('\n');
    $('in-tn-warning').classList.toggle('hidden', !warnings.length);
    for (const l of [...numberLines, ...warnings]) log(l, 'N§4');
    const file = JSON.parse(engine.contactsFile());
    const granted = Object.values(file.grants_issued || {}).some((g) => g.identity === r.identity) || (file.allow || []).includes(r.identity);
    const known = contacts.some((c) => c.did === r.identity);
    $('in-contact').textContent = granted ? 'you granted this identity contact (§19.4)' : known ? 'in your contacts, no grant' : '⚠ unknown identity: not in your contacts, no grant';
    $('in-contact').className = granted || known ? 'small' : 'small warn';
    $('in-policy').textContent = p.policy ? 'their policy: ' + Object.entries(p.policy).map(([k, v]) => `${k}=${v}`).join(', ') : '';
    $('in-downgrade').classList.add('hidden');
    $('view-incoming').classList.remove('hidden');
    // §12.4 OFFERED → ALERTING: policy admitted; progress ringing goes out; the person decides
    if (call?.sid === m.id) call.alerted = true;   // M§13.3: an alerted leg that is not answered here is a call event
    await engine.local({ local: 'alert', session: m.id, ring_timeout: 120 });
    return;
  }
  if (!call || ![m.id, m.session, m.in_reply_to].includes(call.sid)) return;   // not this call: the engine has already acted
  if (m.type === 'answer' && call.media) {
    const sdp = p.transports?.[0]?.sdp;
    if (sdp) await call.media.acceptAnswer(sdp);
  }
  if (m.type === 'error' && m.reason === 'gateway.downgraded') {
    const text = '⚠ ' + downgrade_summary(JSON.stringify((p.detail && p.detail.losses) || []));
    for (const id of ['call-downgrade', 'in-downgrade']) { $(id).textContent = text; $(id).classList.remove('hidden'); }
    log(text, 'G§7');
  }
  if (m.type === 'update') { call.offer = p; call.pendingUpdate = m.id; if (p.answered_by === 'user') $('call-mode').textContent = ''; }   // §14.4 step 3: the screener answered for real
  if (m.type === 'info' && p.about === 'transport:webrtc' && p.data?.candidates && call.media) {
    for (const c of p.data.candidates) await call.media.addRemoteCandidate(c);
  }
}

async function onEmission(e) {
  if (e.timer) { log(`⏱ ${e.name} ${e.timer}${e.seconds ? ` (${e.seconds} s)` : ''}`, '§12.9'); if (e.timer === 'expired') $('call-note').textContent = `${e.name} expired`; return; }
  if (e.media) {
    log(`♫ media ${e.media}`, '§14.1');
    if (e.media === 'start') await flushLocalCandidates();
    if (e.media === 'stop') endCall();
    return;
  }
  if (e.ui) {
    const fields = Object.entries(e).filter(([k]) => k !== 'ui').map(([k, v]) => `${k}=${v}`).join(' ');
    const sec = { progress: '§12.10', answered: '§14.3', offered: '§12.4', missed_call: '§12.11', ended: '§12.4', glare_retry: '§12.6', update_offered: '§12.8',
      update_rejected: '§12.8', introduction_received: '§19.4', granted: '§19.4', introduction_rejected: '§19.4' }[e.ui] || '§12';
    log(`◆ ${e.ui} ${fields}`, sec);
    if (e.ui === 'progress') $('call-note').textContent = e.status === 'ringing' ? 'ringing at the other end' : e.status || '';
    if (e.ui === 'answered') $('call-mode').textContent = e.answered_by === 'screening' ? 'answered in screening mode: they hear you, you do not hear them (§14.4)' : '';
    if (e.ui === 'missed_call') notify(`Missed call from ${nameOf(call?.peer) || short(call?.peer)}`);
    if (e.ui === 'ended') {
      const peer = call?.peer;
      if (call && legs.has(call.sid)) legs.get(call.sid).uiReason = e.reason;   // C§9: a leg that ended without a frame
      const refused = e.reason === 'policy.first-contact-required' && peer;
      // §12.7: a forked invite answered on another device ends this leg; §12.11: never a missed call
      const elsewhere = e.reason === 'session.answered-elsewhere';
      const noRoute = e.reason === 'identity.unknown' && call?.destination;
      $('call-note').textContent = refused ? 'They require an introduction before calls (§19.4). Introduce yourself; once they grant you, call again.'
        : elsewhere ? 'answered on another of your devices (§12.7); not a missed call'
        : noRoute ? `${call.destination}: the gateway found no identity for that number and no route (identity.unknown, N§6.1)`
        : e.reason ? `ended: ${e.reason}` : 'ended';
      const leg = endCall(refused);
      if (leg?.role === 'responder') callEnded(leg, e.reason === 'user.no-answer' ? 'local' : 'remote', e.reason);
      if (leg?.role === 'initiator' && !refused) offerVoicemail(leg, e.reason);
      if (refused) { $('btn-introduce-after').classList.remove('hidden'); $('btn-introduce-after').onclick = () => introduce(peer); }
    }
    if (e.ui === 'introduction_received' && e.token) { notify(`${short(e.from)} used your contact link: granted`); if (!contacts.some((c) => c.did === e.from)) await addContact('', e.from); }
    else if (e.ui === 'introduction_received') notify(`Introduction from ${nameOf(e.from) || short(e.from)}: see Requests`);
    if (e.ui === 'introduction_rejected') notify(`an introduction of yours was declined${e.reason ? ` (${e.reason})` : ''}`);
    if (e.ui === 'granted') { notify(`${nameOf(e.by) || short(e.by)} granted you contact`); closePeerRelay(e.by); }
    return;
  }
  if (e.info) { log(`ℹ info for ${e.info.about}`, '§12.12'); return; }
  if (e.drop) { log(`· dropped: ${e.drop}`); return; }
  if (e.refused) { log(`✗ refused: ${e.refused}`); notify(`Refused: ${e.refused}`); return; }
  if (e.queue) log(`queued ${e.queue.type} for ${short(e.queue.to)}`);
}

function notify(text) { $('call-note').textContent = text; log(text); }

// ---------------------------------------------------------------- calls

/** The ICE servers for a call: Settings, else the operator's, else short-lived TURN credentials minted by the relay's
 *  origin (`/turn`, spec-gap 114), fetched again once half their life is gone; else none (host candidates only). */
async function iceServers() {
  if (settings.ice) return settings.ice;
  if (served.ice) return served.ice;
  if (ice && now() < ice.until - ice.ttl / 2) return ice.servers;
  try {
    const r = await fetch(`${httpOrigin(relayUrl())}/turn`);
    if (!r.ok) { ice = { servers: [], until: now() + 300, ttl: 600 }; log(`no TURN credentials at the relay's origin (${r.status}): host candidates only`, 'B§'); return []; }
    const t = await r.json();
    ice = { servers: t.iceServers || [], until: now() + (t.ttl || 600), ttl: t.ttl || 600 };
    log(`TURN credentials from the relay's origin: ${ice.servers.map((s) => [].concat(s.urls).join(' ')).join('; ')}, valid ${ice.ttl} s`, 'B§');
  } catch (e) { ice = { servers: [], until: now() + 60, ttl: 120 }; log(`the relay's origin did not answer /turn: ${e.message}`, 'B§'); }
  renderNetwork();
  return ice.servers;
}

/** `https://host:port` of a `wss://host:port/dsip` relay URL. */
function httpOrigin(wss) { return wss.replace(/^wss:/, 'https:').replace(/\/dsip\/?$/, ''); }

async function newMedia() {
  return new Media(await iceServers(), {
    candidate: (entry) => { call.pendingLocal.push(entry); if (engine.state(call.sid) === 'ACTIVE') flushLocalCandidates(); },
    track: (stream) => { $('remote').srcObject = stream; },
    state: async (s) => {
      log(`webrtc: ${s}`, 'B§');
      if (!call) return;
      if (s === 'connected') {
        const path = await call.media?.path();
        const via = path ? ` · path ${path.local}↔${path.remote}${path.relayed ? ' (through TURN)' : ' (direct)'}` : '';
        $('call-note').textContent = `media connected (DTLS-SRTP)${via}`;
        if (path) log(`media path ${path.local}↔${path.remote} ${path.protocol}${path.relayed ? ' relayed through TURN' : ' direct'}${path.rtt_ms != null ? `, rtt ${path.rtt_ms} ms` : ''}`, 'B§');
      } else if (s === 'failed') $('call-note').textContent = 'media failed: check ICE servers in Settings';
    },
  });
}

async function flushLocalCandidates() {
  // §12.12: candidates ride in signed info, ACTIVE-only; everything gathered earlier waits here
  if (!call || engine.state(call.sid) !== 'ACTIVE' || !call.pendingLocal.length) return;
  const batch = call.pendingLocal; call.pendingLocal = [];
  engine.setInfoData({ candidates: batch.filter(Boolean), end_of_candidates: batch.some((c) => c === null) });
  await engine.local({ local: 'info', session: call.sid });
}

/** Place a call to a DID; with `destination` (`tel:+…`), `to` is a gateway and the number rides as the invite's
 *  destination (N§4.1). A saved binding is presented on every call as a `tel` claim (N§4). */
async function placeCall(to, video, destination) {
  if (call && engine.state(call.sid) !== 'ENDED') return notify('already in a call');
  pendingVoicemail = null; $('btn-voicemail').classList.add('hidden');
  log(`placing a ${video ? 'video ' : ''}call to ${nameOf(to) || short(to)}${destination ? ` (${destination})` : ''}`, '§12.4');
  call = { sid: engine.newId(), role: 'initiator', peer: to, destination, media: null, pendingLocal: [], pendingUpdate: null, screening: false };
  $('call-peer-name').textContent = nameOf(to) || '';
  $('call-peer-did').textContent = to;
  $('call-basis').textContent = verification_basis(to, '[]');
  const lines = [];
  if (destination) lines.push(`to ${destination} through the gateway ${short(to)}: the number is the invite's destination (N§4.1)`);
  if (settings.binding) lines.push(`presenting ${bindingNumber()} with its binding (N§4)`);
  $('call-number-line').textContent = lines.join(' · ');
  $('call-number-line').classList.toggle('hidden', !lines.length);
  $('call-route').classList.add('hidden');
  $('call-note').textContent = ''; $('call-mode').textContent = '';
  $('call-downgrade').classList.add('hidden');
  $('btn-introduce-after').classList.add('hidden');
  show('call');
  try {
    // §8.1: discovery before the invite. A did:key has no document; the hints tier may name the peer's relay, and a
    // call to someone bound elsewhere goes through that relay on a connection of its own (the hint is not authority:
    // it only says where to try).
    const sid = call.sid;
    const hint = await discover(to);
    if (!call || call.sid !== sid) return;
    if (hint && hint.uri && hint.uri !== relayUrl()) {
      $('call-route').textContent = `via their relay ${hint.uri} (a hint from the nodes, signed by ${short(hint.signer)}, expires in ${Math.max(0, Math.round(hint.expires_at - now()))} s; hint-sourced, not authoritative, §8.1)`;
      $('call-route').classList.remove('hidden');
      const r = await openCallRelay(hint.uri, sid);
      if (!call || call.sid !== sid) { r?.close(); return; }
      if (!r) { log(`their relay ${hint.uri} did not bind us; trying our own relay instead`, '§8.1'); $('call-route').textContent += ' — unreachable; through our own relay'; }
    } else if (hint) { $('call-route').textContent = `their hint names our relay (${hint.uri})`; $('call-route').classList.remove('hidden'); }
    call.media = await newMedia();
    await call.media.capture(video);
    $('local').srcObject = call.media.localStream;
    const sdp = await call.media.offer();
    engine.setVideo(video);
    if (video) engine.setVideoCodecsFromSdp(sdp);
    engine.setSdp(sdp);                                     // B§: SDP as the transport binding object
    engine.ep.set_claims(JSON.stringify(settings.binding ? [{ type: 'tel', number: bindingNumber(), binding: settings.binding }] : []));
    engine.ep.set_invite_patch(destination ? JSON.stringify({ destination }) : 'null');
    await engine.local({ local: 'place_call', session: call.sid, to });
  } catch (err) { notify(`cannot call: ${err.message || err}`); endCall(); }
  renderCall();
}

/** Call a phone number: looked up on the number nodes (N§6 route 1, each binding verified against its own DID's
 *  document held here, the newest winning, N§7); a number nothing resolves is a PSTN number, dialled through the
 *  gateway in Settings as the invite's destination (N§4.1). */
async function callNumber(input) {
  const tn = input.trim().replace(/^tel:/, '').replace(/[\s().-]/g, '');
  if (!/^\+[1-9][0-9]{1,14}$/.test(tn)) return notify('a number is tel:+ and 2 to 15 digits (E.164)');
  const nodes = nodesInEffect();
  if (nodes.length) {
    const bindings = [];
    for (const n of nodes) {
      try {
        const r = await fetch(`${n.replace(/\/$/, '')}/dsip/v1/tn/${encodeURIComponent(tn)}`);
        if (r.ok) for (const b of (await r.json()).bindings || []) if (!bindings.includes(b)) bindings.push(b);
        log(`number ${tn}: ${r.ok ? `${bindings.length} binding(s)` : `${r.status}`} from ${n} (hints tier)`, 'N§6');
      } catch (e) { log(`number ${tn}: ${n} did not answer (${e.message})`, 'N§6'); }
    }
    const sel = JSON.parse(tn_select(tn, JSON.stringify(bindings), JSON.stringify(documents), now(), JSON.stringify(setting('tn_policy') || {})));
    if (sel) {
      log(`number ${tn} → ${sel.did}${sel.attested_by ? ` (attested by ${sel.attested_by})` : ''}${sel.others.length ? `; also claimed by ${sel.others.join(', ')}` : ''}`, 'N§6 · N§7');
      return placeCall(sel.did, false);
    }
    log(`number ${tn}: no binding verifies`, 'N§6');
  }
  const gateway = setting('gateway');
  if (!gateway) return notify(nodes.length ? `${tn} resolves to no identity, and no gateway is set in Settings` : 'calling a number needs nodes or a gateway in Settings');
  log(`number ${tn} → PSTN through gateway ${short(gateway)}, as the invite's destination`, 'N§4.1');
  return placeCall(gateway, false, `tel:${tn}`);
}

/** Look `did` up on the nodes (DHT Hints Profile §10): every frame they return goes through the same §8.3 selection
 *  a node applies (`hint_select`: verified against the subject or its delegation, unexpired, highest `seq`). What
 *  comes back is a hint. */
async function discover(did) {
  const nodes = nodesInEffect();
  if (!nodes.length) return null;
  const frames = [];
  const t0 = performance.now();
  for (const n of nodes) {
    try {
      const r = await fetch(`${n.replace(/\/$/, '')}/dsip/v1/hints/${encodeURIComponent(did)}`);
      const got = r.ok ? (await r.json()).hints || [] : [];
      for (const f of got) if (!frames.includes(f)) frames.push(f);
      log(`hints for ${short(did)}: ${r.ok ? `${got.length} record(s)` : r.status === 404 ? 'none (no overlay at that node)' : r.status} from ${n} in ${Math.round(performance.now() - t0)} ms (hints tier)`, '§8.5 · profile §10');
    } catch (e) { log(`hints for ${short(did)}: ${n} did not answer (${e.message})`, '§8.5'); }
  }
  const out = JSON.parse(hint_select(did, JSON.stringify(frames), JSON.stringify(documents), now()));
  for (const v of out.report) if (v.verdict !== 'accept') log(`   a hint record was refused: ${v.code}${v.detail ? ' ' + v.detail : ''}`, '§8.3');
  if (out.hint) log(`hint for ${short(did)}: ${out.hint.uri} seq ${out.hint.seq}, signed by ${out.hint.signer === did ? 'the subject' : 'delegated device ' + short(out.hint.signer)} — HINT-SOURCED, NOT AUTHORITATIVE (§8.1 rule 6)`, '§8.3');
  else if (frames.length) log(`hint for ${short(did)}: none of ${frames.length} verified`, '§8.3');
  return out.hint;
}

/** A connection to another relay for one call: our hello binds this device there, and the session's frames go
 *  through it (routed by `to` on that relay); closed when the call ends. Resolves to null if it refuses or is not
 *  reachable within 8 s. */
function openCallRelay(uri, sid) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (r) => { if (!settled) { settled = true; resolve(r); } };
    const r = new Relay(uri, engine.ep, {
      bound: (info) => { r.did = info.did; log(`← hello        their relay ${short(info.did)} bound us for this call (in_reply_to matched)`, '§13.2 · §20.5'); done(r); },
      refused: (x) => { log(`✗ their relay's hello rejected: ${x.code}`, '§20.5'); r.close(); done(null); },
      rejected: (code) => { log(`✗ their relay refused our hello: ${code}`, '§13.2'); r.close(); done(null); },
      frame: (text) => engine.inbound(text),
      closed: () => { if (settled && callRelays.get(sid) === r && !r.closedByUs) log(`their relay ${uri} dropped the connection; reconnecting`, '§13.2'); },
      dropped: (f) => log(`✗ their relay not connected: a ${JSON.parse(f).type || 'frame'} was not sent`),
    }, now);
    callRelays.set(sid, r);
    r.connect();
    setTimeout(() => { if (!settled) { r.close(); callRelays.delete(sid); done(null); } }, 8000);
  }).then((r) => { if (!r) callRelays.delete(sid); return r; });
}

/** Publish our reachability hint on the nodes (DHT Hints Profile §10 `POST /dsip/v1/hints`): signed by this
 *  device under its delegation, naming our relay, `seq` = now, ttl the profile's maximum; re-signed at ⅔ of it. */
async function publishReachability() {
  clearInterval(hintTimer); hintTimer = null;
  if (!publishHint() || !relay?.bound) return;
  // Impl: `seq` is the issue time, as the CLI's, but never at or below the last one this browser published: a relay
  // changed within the same second would otherwise tie with the held record and lose to it (§8.3, same seq, live).
  // The last seq is kept in storage, so a reload stays newer too. Two devices of one identity on different relays
  // are not reconciled here (each publishes its own, and the newest wins at a node).
  const seq = Math.max(Math.floor(now()), hintSeq + 1);
  hintSeq = seq; store.set(key('hint_seq'), seq);
  const uri = relayUrl();
  // M§4.2: a did:key identity advertises its mailbox in the hint, as a DSIPMailbox endpoint carrying the service
  // entry's fields; only once the mailbox has bound this device (it serves this identity, spec-gap 115)
  const endpoints = [{ uri }];
  const mb = mailboxOf();
  if (mb && mailboxInfo && mailboxInfo.did === mb.did) endpoints.push({ uri: mb.uri, service: 'DSIPMailbox', mailbox: mb.did, priority: 0, profiles: ['messaging/1.0'], accepts: ['text', 'audio'], voicemail: { max_duration_s: VOICEMAIL_MAX_S } });
  const frame = hint_frame(JSON.stringify(identity), engine.newId(), JSON.stringify(endpoints), HINT_TTL_S, seq, now());
  for (const n of nodesInEffect()) {
    try {
      const r = await fetch(`${n.replace(/\/$/, '')}/dsip/v1/hints`, { method: 'POST', body: frame, headers: { 'content-type': 'text/plain' } });
      const text = r.status === 202 ? `accepted (${(await r.json()).acknowledged ?? '?'} peer(s) acknowledged)` : r.status === 409 ? 'a held record wins (§8.3)' : `${r.status} ${(await r.text()).slice(0, 80)}`;
      log(`hint published → ${n}: ${uri}${endpoints.length > 1 ? ' + mailbox' : ''} seq ${seq} for ${HINT_TTL_S} s: ${text}`, '§8.3 · profile §10');
    } catch (e) { log(`hint not published: ${n} did not answer (${e.message})`, '§8.5'); }
  }
  hintTimer = setInterval(publishReachability, (HINT_TTL_S * 2 / 3) * 1000);
}

async function accept(screening) {
  if (!call || call.role !== 'responder') return;
  call.answered = true;
  $('view-incoming').classList.add('hidden');
  $('call-peer-name').textContent = nameOf(call.peer) || '';
  $('call-peer-did').textContent = call.peer;
  $('call-basis').textContent = $('in-basis').textContent;
  $('call-note').textContent = '';
  $('call-mode').textContent = screening ? 'screening: nothing of yours is sent (§14.4)' : '';
  $('btn-introduce-after').classList.add('hidden');
  show('call');
  try {
    call.pendingLocal = []; call.screening = screening;
    call.media = await newMedia();
    const offerSdp = call.offer.transports?.[0]?.sdp;
    if (!screening) { await call.media.capture(!!call.offer.media?.some((m) => m.type === 'video')); $('local').srcObject = call.media.localStream; }
    engine.setSdp(await call.media.answer(offerSdp, screening));
    await engine.local({ local: 'accept', session: call.sid, answered_by: screening ? 'screening' : 'user' });
  } catch (err) { notify(`cannot answer: ${err.message || err}`); await engine.local({ local: 'decline', session: call.sid }); endCall(); }
  renderCall();
}

async function decline() {
  if (!call) return;
  $('view-incoming').classList.add('hidden');
  const leg = call;
  await engine.local({ local: 'decline', session: call.sid });
  endCall();
  callEnded(leg, 'local', 'user.declined');
}

async function hangup() {
  if (!call) return;
  const st = engine.state(call.sid);
  if (st === 'ACTIVE') await engine.local({ local: 'hangup', session: call.sid });
  else if (st === 'ENDED' || !st) endCall();
  else if (call.role === 'responder') await engine.local({ local: 'decline', session: call.sid });
  else {
    // §12.5: our cancel ends the session for us at once; a late answer that crosses it is answered by the engine
    // with a bye on its own, and neither is a `ui ended` (the person ended it), so the screen is cleared here.
    await engine.local({ local: 'cancel', session: call.sid });
    endCall();
  }
}

async function sendUpdate(escalate) {
  if (!call?.media) return;
  const offeredVideo = !!call.offer?.media?.some((m) => m.type === 'video');
  if (escalate) await call.media.unscreen(offeredVideo);
  else await call.media.addVideo();
  $('local').srcObject = call.media.localStream;
  const sdp = await call.media.offer();
  engine.setVideo(escalate ? offeredVideo : true);
  engine.setVideoCodecsFromSdp(sdp);
  engine.setSdp(sdp);
  const ev = { local: 'update', session: call.sid, id: engine.newId() };
  if (escalate) { ev.answered_by = 'user'; call.screening = false; $('call-mode').textContent = ''; }   // §14.4 step 3
  await engine.local(ev);
  renderCall();
}

async function answerUpdate() {
  if (!call?.pendingUpdate || !call.media) return;
  const id = call.pendingUpdate; call.pendingUpdate = null;
  const wantVideo = !!call.offer.media?.some((m) => m.type === 'video');
  if (wantVideo && !call.screening) { await call.media.addVideo(); $('local').srcObject = call.media.localStream; }
  engine.setSdp(await call.media.answer(call.offer.transports?.[0]?.sdp, call.screening));
  await engine.local({ local: 'answer_update', session: call.sid, in_reply_to: id, answered_by: 'user' });
  renderCall();
}

async function rejectUpdate() {
  if (!call?.pendingUpdate) return;
  const id = call.pendingUpdate; call.pendingUpdate = null;
  await engine.local({ local: 'reject_update', session: call.sid, in_reply_to: id, reason: 'media.unsupported' });
  renderCall();
}

/** M§6.8: no sibling added this device, so it joins by external commit every group its mailbox holds a GroupInfo for,
 *  the personal group first; each member (and the hub) checks the joiner's identity already had a leaf there. No
 *  archive key comes with it: history waits for a sibling to re-send one (M§12.3). */
async function joinAvailable() {
  if (!messenger || !mailboxInfo) return [];
  const groups = JSON.parse(messenger.available());
  if (!groups.length) { log('external join: the mailbox holds no GroupInfo for a group this device is not in', 'M§6.8'); return []; }
  const joined = [];
  for (const g of groups) {
    try {
      const p = awaitEmission((e) => (e.ui === 'joined' && e.group === g.group) || (e.refused && e.refused.includes(g.group)), 30000);
      await driveMailbox(JSON.parse(messenger.external_join(g.group, now())).map((f) => ({ send: f })));
      log(`external commit for the ${g.kind} group ${short(g.group)} sent to its hub ${short(g.hub?.did)}`, 'M§6.8');
      const r = await p;
      if (r.ui === 'joined') joined.push(g.group);
      else log(`external join of ${short(g.group)} refused: ${r.refused}`, 'M§6.8');
    } catch (e) { log(`external join of ${short(g.group)}: ${e.message || e}`, 'M§6.8'); }
  }
  renderMessages();
  return joined;
}

// ---------------------------------------------------------------- call records (Recording Profile C§9)

/** What this device saw of each session leg, by session id: every frame of the session sent or accepted, exactly as
 *  it went (for `evidence`), the invite's and the applied answer's `issued_at`, the answer's media and the relay. */
const legs = new Map();
const TERMINAL = ['bye', 'cancel', 'reject'];

function legFrame(text, dir) {
  const p = payloadOf(text);
  const sid = p.type === 'invite' ? p.id : p.session;
  if (!sid) return;
  let leg = legs.get(sid);
  if (!leg) {
    if (p.type !== 'invite') return;
    const via = callRelays.get(sid)?.did;
    leg = { session: sid, direction: dir === 'out' ? 'outbound' : 'inbound', peer: dir === 'out' ? p.to : p.from, invited_at: p.issued_at,
      relay: via || relayInfo?.did || null, frames: [], answered: false };
    legs.set(sid, leg);
  }
  leg.frames.push({ text, dir, type: p.type, reason: p.reason });
  if (p.type === 'answer' && leg.answered_at == null) {
    leg.answered_at = p.issued_at;
    leg.media = (p.media || []).map((m) => m.type).filter(Boolean);
  }
}

/** After each engine step: a leg whose session became active was answered here; one that ended is recorded. */
function legsChanged() {
  for (const leg of [...legs.values()]) {
    const st = engine.state(leg.session);
    if (st === 'ACTIVE') leg.answered = true;
    if (st === 'ENDED' || st === null) { legs.delete(leg.session); recordLeg(leg); }
  }
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

/** C§9: one `call-record` per leg to the record-keeper named in Settings. `ended_by` and `reason` come from the frame
 *  that ended the leg (the last bye, cancel or reject, else the last error), sent (`local`) or received (`remote`);
 *  a leg that ended without one ended here (a timer, glare). `evidence` is the SHA-256 of each frame's text. The
 *  Messenger derives the outcome and holds the record until the record-keeper's conversation exists. */
async function recordLeg(leg) {
  const keeper = settings.record_keeper;
  if (!keeper) return;
  if (!messenger) { log(`no call record for ${short(leg.session)}: messaging is not running (C§9)`, 'C§9'); return; }
  const end = [...leg.frames].reverse().find((f) => TERMINAL.includes(f.type)) || [...leg.frames].reverse().find((f) => f.type === 'error');
  const evidence = [];
  for (const f of leg.frames) evidence.push(hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(f.text))));
  const input = { session: leg.session, direction: leg.direction, peer: leg.peer, relay: leg.relay || undefined, invited_at: leg.invited_at,
    answered: leg.answered, answered_at: leg.answered_at, ended_by: end ? (end.dir === 'out' ? 'local' : 'remote') : 'local',
    reason: end ? end.reason : leg.uiReason, media: leg.answered ? leg.media : undefined, evidence };
  try {
    const out = JSON.parse(messenger.call_record(keeper, JSON.stringify(input), now()));
    if (out.frames.length) await driveMailbox(out.frames.map((f) => ({ send: f })));
    else await store.set(key('messenger'), JSON.parse(messenger.save()));
    log(`call record for ${short(leg.session)}: ${out.record.outcome}, ended ${out.record.ended_by}${out.record.reason ? ` (${out.record.reason})` : ''}, ${evidence.length} frame hashes; ${out.frames.length ? 'sent to the record-keeper' : `held (${messenger.held_records()}): no conversation with the record-keeper yet`}`, 'C§9');
  } catch (e) { log(`✗ call record for ${short(leg.session)}: ${e.message || e}`, 'C§9'); }
}

/** Records held while no conversation with the record-keeper existed go out once it does (C§9, spec-gap 123). */
async function flushRecords() {
  if (!messenger || !settings.record_keeper || !messenger.held_records()) return;
  try {
    const frames = JSON.parse(messenger.flush_records(settings.record_keeper, now()));
    if (frames.length) { await driveMailbox(frames.map((f) => ({ send: f }))); log(`${frames.length} held call record${frames.length === 1 ? '' : 's'} sent to the record-keeper`, 'C§9'); }
  } catch (e) { log(`✗ held call records: ${e.message || e}`, 'C§9'); }
}

/** M§7.3 "Leaving": propose the removal of this identity's leaves; another member commits it. The conversation is
 *  no longer listed, and nothing more is sent there. */
async function leaveConversation(gid) {
  if (!messenger) return;
  try {
    const out = JSON.parse(messenger.leave(gid, now()));
    await driveMailbox(out);
    if (activeConv === gid) activeConv = null;
    log(`left ${short(gid)}: the removal of this identity's ${out.filter((e) => e.send).length} leaf(s) proposed; another member commits it`, 'M§7.3');
    notify('You left the conversation');
  } catch (e) { notify(`cannot leave: ${e.message || e}`); }
  renderMessages();
}

/** C§5: the user accepts every recorder now in the conversation; the acceptance goes to the personal group so this
 *  identity's other devices accept them too. */
async function acceptRecording(gid) {
  if (!messenger) return;
  try {
    const out = JSON.parse(messenger.accept_recording(gid, now()));
    await driveMailbox(out.frames.map((f) => ({ send: f })));
    log(`recording accepted: ${out.accepted.map(short).join(', ')}${out.frames.length ? '; your other devices are told through the personal group' : ''}`, 'C§5');
  } catch (e) { notify(`${e.message || e}`); }
  renderMessages();
}

/** Make this identity a record-keeper: its device re-delegated with `dsip.record` (C§5, C§9). */
async function becomeRecordKeeper() {
  if (!identity.controller_seed_hex) return notify('only a device holding the identity key can re-delegate itself (§7.4)');
  identity = JSON.parse(redelegate(JSON.stringify(identity), now(), 'dsip.record'));
  await store.set(key('identity'), identity);
  // C§5: a recorder is never in its identity's personal group, so its messaging starts afresh: no group made before
  // it was a recorder (its personal group included) is carried over. Messaging stops first, so a mailbox answer still
  // being handled (the personal group's, on a first bind) cannot save the old state back before the reload
  clearTimeout(messagingStart); messagingStart = null;
  mailboxConn?.close(); mailboxConn = null; mailboxInfo = null; messenger = null;
  await store.del(key('messenger'));
  log('delegation re-issued with dsip.record: this device is a recorder and keeps call records (C§5, C§9); its messaging starts afresh; reloading', 'C§9');
  location.reload();
}

function renderRecords() {
  const keeper = !!messenger?.is_recorder();
  $('records-pane').classList.toggle('hidden', !keeper);
  if (!keeper) return;
  const recs = JSON.parse(messenger.records());
  const key = JSON.stringify(recs.map((r) => [r.device, r.record.session]));
  if ($('record-list').dataset.shown === key) return;
  $('record-list').dataset.shown = key;
  $('record-list').innerHTML = recs.length ? '' : '<li class="muted small">none yet</li>';
  for (const r of recs) {
    const c = r.record, li = document.createElement('li');
    li.className = 'record'; li.dataset.session = c.session; li.dataset.outcome = c.outcome;
    const secs = c.answered_at ? ` · ${c.ended_at - c.answered_at} s` : '';
    li.textContent = `${nameOf(r.from) || short(r.from)} ${c.direction === 'outbound' ? '→' : '←'} ${nameOf(c.peer) || short(c.peer)} · ${c.outcome}${secs} · ended ${c.ended_by}${c.reason ? ` (${c.reason})` : ''} · ${new Date(c.invited_at * 1000).toLocaleTimeString()} · ${(c.evidence || []).length} hashes · device ${short(r.device)}`;
    $('record-list').append(li);
  }
}

/** M§13.3: a callee leg ended; the pinned decision says whether this device records a call event in the personal
 *  group (alerted here, not answered here, never answered elsewhere). */
async function callEnded(leg, endedBy, reason) {
  if (!messenger || !leg) return;
  try {
    const frames = JSON.parse(messenger.call_ended(JSON.stringify({ session: leg.sid, peer: leg.peer, alerted: !!leg.alerted, answered_here: !!leg.answered, ended_by: endedBy, reason: reason || '' }), now()));
    if (frames.length) { await driveMailbox(frames.map((f) => ({ send: f }))); log(`call event for ${short(leg.sid)} to the personal group: ${reason === 'user.declined' && endedBy === 'local' ? 'declined' : 'missed'}`, 'M§13.3'); }
    else log(`no call event for ${short(leg.sid)} (${reason || 'ended'})`, 'M§13.3');
  } catch (e) { log(`call event not sent: ${e.message || e}`, 'M§13.3'); }
  renderMessages();
}

/** M§13.2: after an attempt of ours ended unanswered, offer to record a voicemail when the callee's mailbox entry
 *  carries `voicemail`, we can send to them, and the outcome is one the pinned rule lists. */
async function offerVoicemail(leg, reason) {
  $('btn-voicemail').classList.add('hidden');
  if (!messenger || !reason) return;
  const type = reason === 'session.timeout' ? 'cancel' : 'reject';   // §12.9: our own cancel on T-Establish/T-Ring expiry
  let mb = null;
  try { mb = await peerMailboxEntry(leg.peer); } catch { /* no entry: no offer */ }
  const d = JSON.parse(voicemail_offer(JSON.stringify(mb?.entry ?? null), messenger.can_send(leg.peer), type, reason));
  log(`voicemail ${d.offer ? `offered (up to ${d.max_duration_s ?? '?'} s)` : 'not offered'}: ${type} ${reason}${mb?.entry?.voicemail ? '' : ', the callee advertises no voicemail'}`, 'M§13.2');
  if (!d.offer) return;
  pendingVoicemail = { peer: leg.peer, session: leg.sid, max_s: d.max_duration_s || VOICEMAIL_MAX_S };
  $('btn-voicemail').textContent = 'Leave a voicemail';
  $('btn-voicemail').classList.remove('hidden');
  if (!call) show('call');
}

/** Record the offered voicemail (M§13.1): caller-recorded audio with `purpose: voicemail` and the invite's `session`,
 *  sent end to end in the direct conversation — created first when only a grant is held (M§14.2). */
async function leaveVoicemail() {
  const vm = pendingVoicemail;
  if (!vm) return;
  if (recorder) { await toggleVoice(); return; }
  let conv = JSON.parse(messenger.conversations(now())).find((c) => c.kind === 'direct' && c.peer === vm.peer);
  if (!conv) {
    await messagePeer(vm.peer);
    try { await until(() => JSON.parse(messenger.conversations(now())).find((c) => c.kind === 'direct' && c.peer === vm.peer && c.members.length === 2), 30000); }
    catch { return notify('voicemail: no conversation with them could be opened'); }
    conv = JSON.parse(messenger.conversations(now())).find((c) => c.kind === 'direct' && c.peer === vm.peer);
    show('call');
  }
  await toggleVoice({ gid: conv.group, purpose: 'voicemail', session: vm.session, max_s: vm.max_s });
  $('btn-voicemail').textContent = 'Stop and send voicemail';
  const done = setInterval(() => { if (!recorder) { clearInterval(done); pendingVoicemail = null; $('btn-voicemail').classList.add('hidden'); } }, 200);
}

/** Poll until `fn` returns something truthy. */
function until(fn, ms) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const t = setInterval(() => { const v = fn(); if (v) { clearInterval(t); resolve(v); } else if (Date.now() - t0 > ms) { clearInterval(t); reject(new Error('timeout')); } }, 200);
  });
}

function endCall(stay = false) {
  if (!call) return;
  call.media?.close();
  const cr = callRelays.get(call.sid);
  if (cr) { const sid = call.sid; setTimeout(() => { cr.close(); callRelays.delete(sid); log(`their relay ${cr.url}: connection for the call closed`, '§13.2'); }, 1000); }
  $('local').srcObject = null; $('remote').srcObject = null;
  $('view-incoming').classList.add('hidden');
  const ended = call; call = null;
  renderContacts();
  if (!$('view-call').classList.contains('hidden')) {
    $('call-state').textContent = 'ENDED';
    $('call-title').textContent = 'Call ended';
    if (!stay) setTimeout(() => { if (!call && !pendingVoicemail && !$('view-call').classList.contains('hidden')) show('contacts'); }, 1500);
  }
  return ended;
}

function introduce(to) {
  show('contacts');
  $('introduce-name').textContent = nameOf(to) || '';
  $('introduce-did').textContent = to;
  $('introduce-form').dataset.to = to;
  $('introduce-purpose').value = '';
  $('introduce-form').classList.remove('hidden');
  $('introduce-purpose').focus();
}

async function sendIntroduction(to, purpose, token) {
  const ev = { local: 'introduce', id: engine.newId(), to, purpose };
  if (token) ev.contact_token = token;
  // §8.1: as before a call, the hints tier may say they are bound to another relay; the introduction goes through
  // it on a connection kept open for the answer (their grant comes back on their relay, where we are now bound)
  if (!callRelays.has(to)) {
    const hint = await discover(to).catch(() => null);
    if (hint?.uri && hint.uri !== relayUrl()) {
      const r = await openCallRelay(hint.uri, to);
      if (r) { log(`introduction to ${short(to)} goes through their relay ${hint.uri} (hint-sourced, §8.1); kept open for their answer`, '§19.4'); setTimeout(() => closePeerRelay(to), 600000); }
      else log(`their relay ${hint.uri} did not bind us; introducing through our own relay`, '§8.1');
    }
  }
  await engine.local(ev);
  $('introduce-form').classList.add('hidden');
  notify('introduction sent; it never rings, and silence is a valid answer');
}

/** Close the connection kept to a peer's relay for an introduction, once answered or given up. */
function closePeerRelay(did) {
  const r = callRelays.get(did);
  if (!r) return;
  callRelays.delete(did);
  r.close();
  log(`their relay ${r.url}: connection for the introduction closed`, '§13.2');
}

// ---------------------------------------------------------------- contacts

async function addContact(name, did, number = '') {
  did = did.trim();
  if (!/^did:(key|web):/.test(did)) return notify('a DID starts with did:key: or did:web:');
  if (did === identity.identity) return notify('that is you');
  number = number.trim();
  if (number && !/^\+[1-9][0-9]{1,14}$/.test(number)) return notify('a number is E.164: +15551234567');
  const existing = contacts.find((c) => c.did === did);
  if (existing) { existing.name = name || existing.name; if (number && !(existing.numbers || []).includes(number)) existing.numbers = [...(existing.numbers || []), number]; }
  else contacts.push({ name: name.trim(), did, numbers: number ? [number] : [] });
  await saveContacts();
}

async function removeContact(did) { contacts = contacts.filter((c) => c.did !== did); await saveContacts(); }

// ---------------------------------------------------------------- identity and settings

async function exportToFile() {
  const pass = prompt('Choose a passphrase for the identity file (at least 8 characters). Without it the file is useless; without the file the identity is unrecoverable.');
  if (pass === null) return;
  try {
    const text = await exportIdentity({ ...identity, devices, revoked }, pass);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
    a.download = `${(identity.display_name || 'dsip').replace(/[^\w.-]+/g, '_')}.dsip-identity`;
    a.click();
    URL.revokeObjectURL(a.href);
    log('identity exported', '§7.3');
  } catch (err) { alert(err.message); }
}

async function importFromText(text) {
  const pass = prompt('Passphrase of the identity file:');
  if (pass === null) return;
  try {
    await enrol(await importIdentity(text, pass));
    location.reload();
  } catch (err) { alert(err.message); }
}

/** Enrol this browser as a device of the identity in a file: a fresh device key, its delegation signed by the
 *  identity key (§7.4), all locally. The file's own device key stays with the device that exported it; the file's
 *  device list and revocations come along. Impl: every import makes a new device (a restore too): a key that was in
 *  a file is not known to be only here. */
async function enrol(file) {
  let fresh = JSON.parse(create_identity(file.controller_seed_hex, null, file.display_name || '', now()));
  if (/^did:web:/.test(file.identity || '')) fresh = JSON.parse(rehome(JSON.stringify(fresh), file.identity, now()));   // §7.2: the file's did:web name, the same key
  const known = (file.devices || []).filter((d) => d.device !== fresh.device);
  if (file.device && !known.some((d) => d.device === file.device)) known.push({ device: file.device });
  known.push({ device: fresh.device, enrolled: Math.floor(now()) });
  await store.set(key('identity'), fresh);
  await store.set(key('devices'), known);
  await store.set(key('revoked'), file.revoked || []);
  await store.del(key('engine.contacts'));
  return fresh;
}

/** Revoke another device of this identity (§7.4, v0.8): the record is signed by the identity key, not this device's,
 *  and covers delegations issued at or before now, so the device can be enrolled again later with a fresh delegation.
 *  It goes to the relay (the only distribution a did:key identity has here) and is held by this engine. */
async function revoke(device) {
  const reason = (prompt('Why? lost, compromised, retired or policy (the §7.4 registry)', 'lost') || '').trim();
  if (!reason) return;
  if (!['lost', 'compromised', 'retired', 'policy'].includes(reason)) return alert('the reason must be lost, compromised, retired or policy');
  const at = Math.floor(now());
  const frame = revocation_frame(JSON.stringify(identity), engine.newId(), device, reason, now());
  engine.ep.hold_revocation(frame);
  relay.send(frame);
  log(`→ delegation-revocation of ${short(device)} (${reason}) to the relay; held here`, '§7.4');
  notify(`device ${short(device)} revoked: the relay ends its binding and refuses its next hello`);
  revoked.push({ device, reason, at, frame });
  devices = devices.filter((d) => d.device !== device);
  await store.set(key('devices'), devices);
  await store.set(key('revoked'), revoked);
  renderDevices();
}

async function setRecordKeeper(did) {
  settings.record_keeper = did || undefined;
  await saveSettings(); renderSettings();
  log(did ? `record-keeper: ${did}; a call record goes to it after every call (C§9)` : 'no record-keeper: no call records are sent', 'C§9');
  flushRecords();
}

async function saveSettings() { await store.set(key('settings'), settings); }

// ---------------------------------------------------------------- relay

function relayUrl() { return settings.relay || served.relay || `wss://${location.host}/dsip`; }

function connect() {
  relay?.close();
  renderRelay(`connecting to ${relayUrl()}…`, '');
  relay = new Relay(relayUrl(), engine.ep, {
    bound: (r) => {
      relayInfo = r;
      if (onBound) { const f = onBound; onBound = null; f(); }
      renderRelay(`relay ${short(r.did)}`, 'ok');
      $('relay-caps').textContent = `relay ${r.did}: ${JSON.stringify(r.capabilities)}`;
      log(`← hello        relay ${short(r.did)} bound (in_reply_to matched)`, '§13.2 · §20.5');
      ice = null; iceServers().catch(() => {});   // credentials are the relay's origin's: fetch them on each bind
      publishReachability();
    },
    refused: (r) => { renderRelay(`relay hello refused: ${r.code}`, 'bad'); log(`✗ relay hello rejected: ${r.code} (anti-splicing)`, '§20.5'); },
    rejected: (code) => {
      const revokedHere = code === 'delegation-revoked';
      renderRelay(revokedHere ? 'this device was revoked: its delegation no longer verifies (§7.4)' : `relay refused our hello: ${code}`, 'bad');
      log(`✗ relay refused our hello: ${code}${revokedHere ? '; this device is revoked, not reconnecting' : ''}`, '§13.2 · §7.4');
      if (revokedHere) notify('This device was revoked by your identity. If that was a mistake, enrol it again from the identity file (a new delegation).');
    },
    frame: (text) => engine.inbound(text),
    closed: () => { if (!relay.closedByUs && !relay.rejected) renderRelay('disconnected, reconnecting…', 'bad'); },
    dropped: (f) => log(`✗ not connected: a ${JSON.parse(f).type || 'frame'} was not sent`),
  }, now);
  relay.connect();
}

// ---------------------------------------------------------------- boot

async function startEngine() {
  engine = new Engine(Endpoint, identity, { first_contact_required: !!settings.first_contact_required }, now);
  engine.loadContactsFile(await store.get(key('engine.contacts')));
  for (const r of revoked) engine.ep.hold_revocation(r.frame);   // §7.4: revocations this identity issued apply here too
  for (const d of Object.values(documents)) engine.ep.add_document(JSON.stringify(d));   // §8.1: documents held
  engine.on = {
    send: (frame, meta) => {
      // a session placed through the peer's own relay stays there, an introduction through the relay their hint
      // named (keyed by their DID); everything else goes through ours
      const via = callRelays.get(meta.session) || callRelays.get(meta.to);
      (via || relay).send(frame); log(`→ ${meta.type.padEnd(12)} to ${short(meta.to)}${via ? ` via ${via.url}` : ''}`, '§12.4');
      if (meta.type === 'reject' && payloadOf(frame).reason === 'policy.first-contact-required') log(`refused a call from ${short(meta.to)} without ringing: first contact required`, '§19.4');
    },
    frame: legFrame,
    received: onReceived,
    emission: onEmission,
    rejected: (code, detail) => log(`✗ inbound rejected: ${code} ${detail || ''}`, '§10.2'),
    changed: () => { persist(); renderContacts(); renderCall(); renderLinks(); messenger?.set_grants(JSON.stringify(heldGrantFrames())); legsChanged(); },
  };
  engine.startTimers();
  connect();
  startMessaging();
}

// ---------------------------------------------------------------- messaging (stage 6)

/** Grants held from others as `{identity: compact}` (§19.4: the grantee holds the signed grant; presented at M§14.2). */
function heldGrantFrames() {
  const file = JSON.parse(engine.contactsFile());
  const out = {};
  for (const [id, g] of Object.entries(file.grants_held || {})) if (file.grant_frames?.[id]) out[g.identity] = file.grant_frames[id];
  return out;
}

/** Start (or restart) the messaging device: a `Messenger` on this identity's mailbox (M§4.2), bound with our hello
 *  (M§4.3); its state is restored from storage and saved after every step (spec-gap 44). */
let messagingStart = null;   // a restart asked for twice in quick succession (relay and mailbox settings) starts once
function startMessaging() {
  clearTimeout(messagingStart);
  messagingStart = setTimeout(() => { messagingStart = null; startMessagingNow().catch((e) => log(`messaging: ${e.message || e}`, 'M§4')); }, 50);
}

async function startMessagingNow() {
  mailboxConn?.close(); mailboxConn = null; mailboxInfo = null; messenger = null;
  const mb = mailboxOf();
  renderMessages();
  if (!mb) return;
  // M§4.3: the delegation must carry dsip.messaging; an identity made before stage 6 is re-delegated here when its
  // identity key is on this device
  const saved = await store.get(key('messenger'));
  try {
    let m = new Messenger(JSON.stringify(identity), mb.did, mb.uri, saved ? JSON.stringify(saved) : undefined, now());
    if (!m.delegation_ok()) {
      if (!identity.controller_seed_hex) { log('messaging needs a delegation with dsip.messaging (M§4.3): enrol this device again from the identity file', 'M§4.3'); renderMessages(); return; }
      identity = JSON.parse(redelegate(JSON.stringify(identity), now()));
      await store.set(key('identity'), identity);
      log('delegation re-issued with dsip.messaging (M§4.3, §7.4): reloading', 'M§4.3');
      location.reload();
      return;
    }
    m.set_read_disclosed(!!settings.read_disclosed, now());
    if (settings.hub_timeout_s) m.set_hub_timeout(settings.hub_timeout_s);   // M§9.4: the device's own threshold
    messenger = m;
  } catch (e) { log(`messaging not started: ${e.message || e}`, 'M§4'); renderMessages(); return; }
  messenger.set_grants(JSON.stringify(heldGrantFrames()));
  clearInterval(messagingTick);
  messagingTick = setInterval(() => { if (messenger === m && mailboxInfo) driveMailbox(m.tick(now())).catch(() => {}); }, 5000);
  for (const d of Object.values(documents)) messenger.add_document(JSON.stringify(d));
  // Every callback belongs to this connection: a restart replaces `mailboxConn`, and the old socket's late close or
  // frame must not touch the state of the new one.
  const m = messenger;
  let conn = null;
  const mine = () => mailboxConn === conn && messenger === m;
  conn = new Relay(mb.uri, m, {
    bound: async (r) => {
      if (!mine()) return;
      if (r.did !== mb.did) {   // M§4.2: the mailbox's hello must be signed under the DID the entry names
        log(`✗ mailbox at ${mb.uri} is ${short(r.did)}, not ${short(mb.did)}: not used`, 'M§4.2');
        conn.close(); renderMessages(); return;
      }
      mailboxInfo = r;
      log(`← hello        mailbox ${short(r.did)} bound us (in_reply_to matched); ${r.capabilities?.mailbox?.hub ? 'a hub' : 'no hub'}, modes ${(r.capabilities?.mailbox?.modes || []).join('/')}`, 'M§4.3 · §20.5');
      await driveMailbox(messenger.on_bound(now()));                      // pending items again, then sync live (M§9.3, M§5.4)
      await driveMailbox([messenger.key_packages_frame(2, now())]);        // M§5.5: fresh KeyPackages on every bind
      if (messenger.is_recorder()) log('this device is a recorder: it never joins its identity\'s personal group (C§5)', 'C§5');
      else if (!messenger.personal()) {
        // M§7.1: the identity's first messaging device creates the personal group; a device that knows of siblings
        // (the identity file it was enrolled from listed them) waits to be added by one of them (M§12.3)
        const siblings = devices.filter((d) => d.device !== identity.device);
        if (!siblings.length) { try { await driveMailbox(messenger.create_personal(now())); log('creating the personal group at the mailbox', 'M§7.1'); } catch (e) { log(`personal group: ${e.message || e}`, 'M§7.1'); } }
        else {
          log(`waiting for another device of this identity (${siblings.map((d) => short(d.device)).join(', ')}) to add this one to the personal group (M§12.3); joining by external commit in ${EXTERNAL_JOIN_WAIT_S} s if none does (M§6.8)`, 'M§12.3');
          clearTimeout(externalJoinTimer);
          externalJoinTimer = setTimeout(() => { if (mine() && !messenger.personal()) joinAvailable(); }, EXTERNAL_JOIN_WAIT_S * 1000);
        }
      }
      publishReachability();                                               // the hint now names the mailbox too (M§4.2)
      flushRecords();                                                      // C§9: records held while the conversation did not exist
      renderMessages();
      reconcileDevices();                                                  // M§12.3: siblings this browser knows of join the groups
    },
    refused: (x) => { if (mine()) log(`✗ mailbox hello rejected: ${x.code}`, '§20.5'); },
    rejected: (code) => { if (mine()) { log(`✗ mailbox refused our hello: ${code}`, 'M§4.3'); renderMessages(); } },
    frame: async (text) => { if (mine()) await driveMailbox(m.inbound(text, now())); },
    closed: (was) => { if (was && mine()) { mailboxInfo = null; log(`mailbox ${mb.uri} dropped the connection; reconnecting`, '§13.2'); renderMessages(); } },
    dropped: (f) => { if (mine()) log(`✗ mailbox not connected: a ${payloadOf(f).type || 'frame'} was not sent`); },
  }, now);
  mailboxConn = conn;
  conn.connect();
  log(`messaging: mailbox ${mb.uri} (${short(mb.did)})`, 'M§4.2');
}

/** Act on what the Messenger returned (a JSON array of emissions, or of frames): send frames to the mailbox, log
 *  and render events, then save its state (MLS and delivery state together, spec-gap 44). */
async function driveMailbox(result) {
  const list = typeof result === 'string' ? JSON.parse(result) : result;
  const m = messenger;
  for (const e of list) {
    if (typeof e === 'string') { mailboxConn.send(e); log(`→ ${payloadOf(e).type?.padEnd(12)} to mailbox${payloadOf(e).class ? ` (${payloadOf(e).class})` : ''}`, 'M§5'); continue; }
    if (e.send === '') continue;   // M§9.4: queued behind an unreachable hub, or kept for a successor
    if (e.send) { mailboxConn.send(e.send); const p = payloadOf(e.send); log(`→ ${(p.type || '').padEnd(12)} to ${p.to === mailboxOf()?.did ? 'mailbox' : 'hub ' + short(p.to)}${p.class ? ` (${p.class})` : ''}`, 'M§5'); }
    else if (e.sync) { const f = messenger.sync_frame(false, now()); mailboxConn.send(f); log('→ sync         after a refused deposit (M§6.5 spec-gap 58; M§7.4 a group that moved)', 'M§6.5'); }
    else if (e.ui) onMessagingUi(e);
    else if (e.refused) { log(`✗ refused: ${e.refused}`, 'M§16'); notify(`Messaging: ${e.refused}`); }
    else if (e.error) log(`✗ messaging error: ${e.error}`, 'M§5');
    else if (e.rejected) log(`✗ mailbox frame rejected: ${e.rejected.code}${e.rejected.reason ? ' ' + e.rejected.reason : ''}`, '§10.2');
    else if (e.drop) log(`· mailbox: ${e.drop}`);
    else if (e.successor_due) successorDue(e.successor_due);
    for (let i = waiters.length - 1; i >= 0; i--) if (waiters[i].pred(e)) waiters.splice(i, 1)[0].resolve(e);
  }
  // a messenger stopped meanwhile (messaging restarted, or the device became a recorder) is not saved over its successor
  if (m && m === messenger) await store.set(key('messenger'), JSON.parse(m.save()));
  renderMessages();
}

function onMessagingUi(e) {
  const sec = { joined: 'M§6.6', committed: 'M§6.5', personal: 'M§7.1', message: 'M§8.1', sent: 'M§9.2', receipt: 'M§10.2', receipt_sent: 'M§10.2', epoch: 'M§7.3', removed: 'M§7.3',
    key_packages_uploaded: 'M§5.5', archive_key: 'M§12.1', granted: 'M§14.1', request: 'M§14.1', duplicate: 'M§8.5', self: 'spec-gap 47', hold: 'M§6.5', released: 'M§6.5', conflict: 'M§6.5',
    archive: 'M§12.2', archived: 'M§12.2', archive_held: 'M§12.3', history: 'M§12.3', history_receipt: 'M§12.2', history_applied: 'M§12.2', read_private_kept: 'M§10.5',
    call_record: 'C§9', recording_accepted: 'C§5', receipt_withheld: 'C§5', left: 'M§7.3', leave_proposed: 'M§7.3', leave_committing: 'M§7.3', leave_proposals: 'M§7.3', leave_proposal_refused: 'M§7.3', hub_down: 'M§9.4', hub_retry: 'M§9.4', hub_back: 'M§9.4', handed_over: 'M§9.4', successor: 'M§7.5', successor_declined: 'M§7.5', successor_left: 'M§7.5', hub_moved: 'M§7.4', moved_check: 'M§7.4', hub_arriving: 'M§7.4', hub_arrival_expired: 'M§7.4' }[e.ui] || 'M§';
  const fields = Object.entries(e).filter(([k]) => k !== 'ui' && k !== 'text').map(([k, v]) => `${k}=${typeof v === 'string' ? short(v) : JSON.stringify(v)}`).join(' ');
  log(`◇ ${e.ui} ${fields}`, sec);
  if (e.ui === 'message') { if (!activeConv) activeConv = e.group; notify(`Message from ${nameOf(e.from) || short(e.from)}`); }
  if (e.ui === 'joined' && e.kind === 'direct' && e.members.includes(settings.record_keeper)) setTimeout(flushRecords, 0);
  if (e.ui === 'leave_committing') notify(`${nameOf(e.identity) || short(e.identity)} left a conversation; this device commits their removal`);
  if (e.ui === 'left') notify('another of your devices left a conversation');
  if (e.ui === 'call_record') notify(`call record from ${nameOf(e.from) || short(e.from)}: ${e.outcome}`);
  if (e.ui === 'joined' && e.kind === 'direct') { activeConv = activeConv || e.group; notify(`${nameOf(e.members.find((m) => m !== identity.identity)) || 'someone'} opened a conversation with you`); }
  if (e.ui === 'committed' && e.device) notify(`device ${short(e.device)} added to ${e.personal ? 'the personal group' : 'a conversation'} (epoch ${e.epoch})`);
  else if (e.ui === 'committed' && e.added) notify(`conversation with ${nameOf(e.added) || short(e.added)} is up (epoch ${e.epoch})`);
  if (e.ui === 'epoch' && e.added?.length) notify(`${e.added.map((a) => { const [who, dev] = a.split('#'); return `${who === identity.identity ? 'your' : `${nameOf(who) || short(who)}'s`} device ${short(dev)}`; }).join(', ')} joined (epoch ${e.epoch})`);
  if (e.ui === 'roster' || e.ui === 'hub_moved') notify(rosterLine(e));
  if (e.ui === 'joined' && e.kind === 'group') { activeConv = activeConv || e.group; notify(`you were added to a group with ${e.members.filter((m) => m !== identity.identity).map((m) => nameOf(m) || short(m)).join(', ')}`); }
  if (e.ui === 'removed' && !e.left) notify(`${e.by ? nameOf(e.by) || short(e.by) : 'a member'} removed you from a conversation`);
  if (e.ui === 'hub_down') notify(`the hub of a conversation is unreachable: messages wait (M§9.4)`);
  if (e.ui === 'hub_back') notify('the hub answers again: pending messages sent');
  if (e.ui === 'successor') { if (activeConv === e.of) activeConv = e.group; notify(`the conversation continues in a successor group (its old hub is gone, M§7.5)`); }
  if (e.ui === 'history') notify(`history: ${e.from === identity.identity ? 'you' : nameOf(e.from) || short(e.from)} #${e.seq}`);
  if (e.ui === 'request') notify(`Message request from ${short(e.from)}: see Messages`);
  if (e.ui === 'granted') notify(`${nameOf(e.by) || short(e.by)} granted you dsip.message`);
}

/** Wait for one Messenger emission on the mailbox connection. */
function awaitEmission(pred, ms = 15000) {
  return new Promise((resolve, reject) => {
    const w = { pred, resolve };
    waiters.push(w);
    setTimeout(() => { const i = waiters.indexOf(w); if (i >= 0) { waiters.splice(i, 1); reject(new Error('no answer from the mailbox')); } }, ms);
  });
}

/** The peer's mailbox (M§4.2, §8.1): its DID document's entry when held here, else the DSIPMailbox endpoint of its
 *  reachability hint on the nodes (a hint: never authority). `{did, uri, source}` or null. */
async function peerMailbox(did) {
  const hint = did.startsWith('did:web:') && documents[did] ? null : await discover(did);
  const sel = JSON.parse(mailbox_select(JSON.stringify(documents[did] ?? null), JSON.stringify(hint?.endpoints || [])));
  if (!sel.selected) return null;
  log(`mailbox of ${short(did)}: ${sel.uri} ${short(sel.selected)} (${sel.source === 'hint' ? 'HINT-SOURCED, NOT AUTHORITATIVE, §8.1 rule 6' : 'from their DID document, §8.1'})`, 'M§4.2');
  return { did: sel.selected, uri: sel.uri, source: sel.source, entry: sel.entry };
}
const peerMailboxEntry = peerMailbox;

/** A short-lived connection to another mailbox for one `key-package-fetch` (M§5.5): bound with our hello, the
 *  answer returned, closed. */
function fetchFromMailbox(mb, target, successorOf) {
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = (fn) => { if (!done) { done = true; r.close(); fn(); } };
    const r = new Relay(mb.uri, messenger, {
      bound: (info) => {
        if (info.did !== mb.did) return finish(() => reject(new Error(`their mailbox is ${short(info.did)}, not ${short(mb.did)}`)));
        log(`← hello        their mailbox ${short(info.did)} bound us (in_reply_to matched)`, 'M§4.3 · §20.5');
        r.send(messenger.fetch_frame(mb.did, target, now(), successorOf));
        log(`→ key-package-fetch for ${short(target)} to their mailbox${heldGrantFrames()[target] ? ', presenting their grant' : ', no grant held'}`, 'M§5.5 · M§14.2');
      },
      refused: (x) => finish(() => reject(new Error(`their mailbox's hello rejected: ${x.code}`))),
      rejected: (code) => finish(() => reject(new Error(`their mailbox refused our hello: ${code}`))),
      frame: (text) => {
        for (const e of JSON.parse(messenger.inbound(text, now()))) {
          if (e.key_packages) return finish(() => resolve(e.key_packages));
          if (e.error) return finish(() => reject(new Error(e.error)));
          if (e.rejected) return finish(() => reject(new Error(`frame rejected: ${e.rejected.code}`)));
        }
      },
      closed: () => { if (!done) finish(() => reject(new Error('their mailbox closed the connection'))); },
      dropped: () => {},
    }, now);
    r.connect();
    setTimeout(() => finish(() => reject(new Error('their mailbox did not answer in 15 s'))), 15000);
  });
}

/** Open (or create, M§7.2) the direct conversation with `did`: the peer's mailbox found, its KeyPackages fetched with
 *  the grant we hold, our own other devices' too, the group created at our mailbox and the add committed. */
async function messagePeer(did) {
  if (!messenger) return notify('messaging needs a mailbox in Settings → Network');
  show('messages');
  messenger.set_grants(JSON.stringify(heldGrantFrames()));   // grants held since the messenger started (§19.4)
  const existing = JSON.parse(messenger.conversations(now())).find((c) => c.kind === 'direct' && c.peer === did);
  if (existing) { activeConv = existing.group; renderMessages(); return; }
  if (!mailboxInfo) return notify('the mailbox is not bound yet');
  $('thread-title').textContent = `opening a conversation with ${nameOf(did) || short(did)}…`;
  try {
    const mb = await peerMailbox(did);
    if (!mb) throw new Error('no mailbox found for them: no document held, and no DSIPMailbox hint on the nodes');
    const theirs = await fetchFromMailbox(mb, did);
    log(`key packages of ${short(did)}: ${(theirs.key_packages || []).length} one-time${theirs.last_resort ? ' + last resort' : ''}`, 'M§5.5');
    // M§7.2: our own other devices join in the same commit; our mailbox is asked over the bound connection
    let own = null;
    try {
      const p = awaitEmission((e) => (e.key_packages && e.key_packages.subject === identity.identity) || e.error, 8000);
      mailboxConn.send(messenger.fetch_frame(mailboxOf().did, identity.identity, now()));
      const got = await p;
      if (got.error) throw new Error(got.error);
      own = got.key_packages;
    } catch (e) { log(`own devices: none added (${e.message})`, 'M§7.2'); }
    const frames = messenger.create_direct(did, JSON.stringify(theirs), own ? JSON.stringify(own) : undefined, now());
    await driveMailbox(frames);
    log(`conversation with ${short(did)} created at our mailbox (hub); the add goes out once the hub holds the group`, 'M§7.2 · M§6.5');
    activeConv = JSON.parse(messenger.conversations(now())).find((c) => c.kind === 'direct' && c.peer === did)?.group || activeConv;
  } catch (e) { notify(`cannot message ${nameOf(did) || short(did)}: ${e.message || e}`); log(`✗ ${e.message || e}`, 'M§7.2'); }
  renderMessages();
}

/** Our own other devices' KeyPackages for a new group (M§7.2, M§7.3: they join in the same commit), or null. */
async function ownForNewGroup() {
  try { return await fetchOwnKeyPackages(); } catch (e) { log(`own devices: none added (${e.message})`, 'M§7.2'); return null; }
}

/** Create a group conversation (M§7.3) with `dids`: each one's mailbox found and its KeyPackages fetched with the grant
 *  we hold (M§14.2), our own other devices' too, the group created at our mailbox and every add in one commit. */
async function createGroup(dids) {
  if (!messenger || !mailboxInfo) return notify('messaging is not connected');
  messenger.set_grants(JSON.stringify(heldGrantFrames()));
  try {
    const targets = {};
    for (const did of dids) {
      const mb = await peerMailbox(did);
      if (!mb) throw new Error(`no mailbox found for ${nameOf(did) || short(did)}`);
      targets[did] = await fetchFromMailbox(mb, did);
      log(`key packages of ${short(did)}: ${(targets[did].key_packages || []).length} one-time${targets[did].last_resort ? ' + last resort' : ''}`, 'M§5.5');
    }
    const own = await ownForNewGroup();
    const before = new Set(JSON.parse(messenger.conversations(now())).map((c) => c.group));
    await driveMailbox(messenger.create_group(JSON.stringify(targets), own ? JSON.stringify(own) : undefined, now()));
    activeConv = JSON.parse(messenger.conversations(now())).find((c) => !before.has(c.group))?.group || activeConv;
    log(`group with ${dids.map((d) => nameOf(d) || short(d)).join(', ')} created at our mailbox (hub); the adds go out once the hub holds it`, 'M§7.3 · M§6.5');
  } catch (e) { notify(`cannot create the group: ${e.message || e}`); log(`✗ ${e.message || e}`, 'M§7.3'); }
  show('messages');
  renderMessages();
}

/** Add the identity `did` to the group conversation `gid` (M§7.3): its KeyPackages fetched with our grant, one commit. */
async function addMember(gid, did) {
  if (!messenger || !mailboxInfo) return;
  messenger.set_grants(JSON.stringify(heldGrantFrames()));
  try {
    const mb = await peerMailbox(did);
    if (!mb) throw new Error(`no mailbox found for ${nameOf(did) || short(did)}`);
    const kps = await fetchFromMailbox(mb, did);
    await driveMailbox([{ send: messenger.add_member(gid, did, JSON.stringify(kps), now()) }]);
    log(`adding ${short(did)} to ${short(gid)}`, 'M§7.3');
  } catch (e) { notify(`cannot add ${nameOf(did) || short(did)}: ${e.message || e}`); }
  renderMessages();
}

/** Remove the member identity `did` from `gid`, every device of it (M§7.3; members check the commit, spec-gap 126). */
async function removeMember(gid, did) {
  if (!messenger) return;
  try {
    await driveMailbox([{ send: messenger.remove_member(gid, did, now()) }]);
    log(`removing ${short(did)} from ${short(gid)}: every device of it`, 'M§7.3');
  } catch (e) { notify(`cannot remove ${nameOf(did) || short(did)}: ${e.message || e}`); }
  renderMessages();
}

/** Move the conversation `gid` to our own mailbox as its hub (M§7.4); on `accepted` our mailbox follows and the new
 *  hub is bootstrapped with the GroupInfo and `handover_seq`. */
async function moveHub(gid) {
  if (!messenger) return;
  try {
    await driveMailbox([{ send: messenger.move_hub(gid, now()) }]);
    log(`moving ${short(gid)} to our mailbox as its hub`, 'M§7.4');
  } catch (e) { notify(`cannot move the conversation: ${e.message || e}`); }
  renderMessages();
}

/** One roster change as members see it (M§7.3: attributed to the committing identity), or a hub move (M§7.4). */
function rosterLine(r) {
  const who = (d) => (d === identity.identity ? 'you' : nameOf(d) || short(d));
  const by = r.by ? who(r.by) : 'a device that no longer authenticates';
  if (r.hub) return `${by} moved the conversation's hub to ${r.hub === mailboxOf()?.did ? 'your mailbox' : `mailbox ${short(r.hub)}`}`;
  const parts = [];
  if (r.added.length) parts.push(`${by} added ${r.added.map(who).join(', ')}`);
  if (r.removed.length) parts.push(`${by} removed ${r.removed.map(who).join(', ')}`);
  for (const l of r.left) parts.push(`${who(l)} left${r.by && r.by !== l ? ` (removal committed by ${by})` : ''}`);
  return parts.join('; ');
}

/** M§9.4 → M§7.5: a group's hub has been unreachable past the threshold. Fetch the KeyPackages of the other
 *  identities of its last roster from their mailboxes, `successor_of` naming the dead group (served without a grant
 *  when the group is registered for them, spec-gap 61), and create the successor at our own mailbox; the pending items
 *  follow once it holds its members. A failure is retried with the §13.2 backoff (spec-gap 72). */
const successorBusy = new Set();
async function successorDue(d) {
  if (successorBusy.has(d.group)) return;
  successorBusy.add(d.group);
  try {
    log(`hub of ${short(d.group)} unreachable past the threshold: creating its successor${d.peers.length ? ` with ${d.peers.map((p) => nameOf(p) || short(p)).join(', ')}` : ''}`, 'M§9.4 · M§7.5');
    const kps = {};
    for (const peer of d.peers) {
      const mb = await peerMailbox(peer);
      if (!mb) throw new Error(`no mailbox found for ${short(peer)}`);
      kps[peer] = await fetchFromMailbox(mb, peer, d.group);
      log(`key packages of ${short(peer)} for the successor: ${(kps[peer].key_packages || []).length} one-time${kps[peer].last_resort ? ' + last resort' : ''}`, 'M§7.5');
    }
    const frames = JSON.parse(messenger.create_successor(d.group, JSON.stringify(kps), now()));
    await driveMailbox(frames.map((f) => ({ send: f })));
    log(`successor of ${short(d.group)} created at our mailbox; the members are added once the hub holds it`, 'M§7.5');
    if (activeConv === d.group) activeConv = JSON.parse(messenger.conversations(now())).find((c) => c.predecessors.includes(d.group))?.group || activeConv;
  } catch (e) {
    messenger.successor_failed(d.group);
    log(`successor of ${short(d.group)} not created: ${e.message || e}; retried`, 'M§9.4');
  } finally { successorBusy.delete(d.group); }
}

/** Our own identity's KeyPackage directory answer (M§5.5), asked of our mailbox on the bound connection. */
async function fetchOwnKeyPackages() {
  const p = awaitEmission((e) => (e.key_packages && e.key_packages.subject === identity.identity) || e.error, 10000);
  mailboxConn.send(messenger.fetch_frame(mailboxOf().did, identity.identity, now()));
  const got = await p;
  if (got.error) throw new Error(got.error);
  return got.key_packages;
}

/** M§12.3, M§6.7: every device this browser knows of (the Devices list) that is not yet in the personal group and
 *  every conversation is added there by this device, personal group first; after that add every live archive key
 *  is re-sent so the new device reads the history. One reconciliation at a time; nothing when there is nothing to do. */
async function reconcileDevices() {
  if (!messenger || !mailboxInfo || !messenger.personal()) return;
  if (reconciling) return reconciling;
  reconciling = (async () => {
    for (const d of devices.map((d) => d.device).filter((d) => d !== identity.device)) {
      const groups = JSON.parse(messenger.groups_for_new_device(d, now()));
      for (const gid of groups) {
        if (!messenger || !mailboxInfo) return;
        try {
          const kps = await fetchOwnKeyPackages();
          if (!(kps.key_packages || []).length && !kps.last_resort) { log(`device ${short(d)}: no KeyPackage at the mailbox yet (it uploads on its first bind, M§5.5)`, 'M§12.3'); return; }
          const done = awaitEmission((e) => (e.ui === 'committed' && e.device === d && e.group === gid) || (e.refused && /commit|add/.test(e.refused)), 30000);
          await driveMailbox([{ send: messenger.add_device(gid, d, JSON.stringify(kps), now()) }]);
          log(`adding device ${short(d)} to ${gid === messenger.personal() ? 'the personal group' : 'a conversation'}`, 'M§12.3 · M§6.7');
          const r = await done;
          if (r.refused) { log(`device ${short(d)}: ${r.refused}`, 'M§12.3'); return; }
          if (r.personal) { await driveMailbox(messenger.resend_archive_keys(now())); log(`re-sent ${JSON.parse(messenger.archive_keys()).length} archive key(s) to the personal group for ${short(d)}`, 'M§12.3'); }
        } catch (e) { log(`device ${short(d)}: ${e.message || e}`, 'M§12.3'); return; }
      }
    }
  })().finally(() => { reconciling = null; renderMessages(); });
  return reconciling;
}

// ---------------------------------------------------------------- voice messages and blobs (M§8.4, M§5.6)

const b64u = {
  encode: (bytes) => { let s = ''; const u = new Uint8Array(bytes); for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); },
  decode: (text) => { const bin = atob(text.replace(/-/g, '+').replace(/_/g, '/')); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; },
};

/** The mailbox's blob endpoint, from its hello capabilities (M§4.3). */
function blobEndpoint() { return mailboxInfo?.capabilities?.mailbox?.blob_endpoint || null; }

/** Start or stop recording a voice message for the open conversation; on stop it is sealed, uploaded and sent. */
async function toggleVoice(opts = {}) {
  if (!messenger || !(opts.gid || activeConv)) return;
  if (recorder) { recorder.rec.stop(); return; }
  if (!blobEndpoint()) return notify('the mailbox advertises no blob endpoint (M§4.3)');
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const mime = ['audio/ogg;codecs=opus', 'audio/webm;codecs=opus', 'audio/ogg', 'audio/webm'].find((m) => window.MediaRecorder?.isTypeSupported?.(m)) || '';
    const rec = new MediaRecorder(stream, mime ? { mimeType: mime } : undefined);
    recorder = { rec, chunks: [], started: Date.now(), stream, gid: opts.gid || activeConv, purpose: opts.purpose || 'voice-message', session: opts.session };
    // M§13.2: a voicemail recording stops at the callee's max_duration_s
    if (opts.max_s) { const r = recorder; setTimeout(() => { if (recorder === r) { log(`voicemail: stopped at the callee's limit of ${opts.max_s} s`, 'M§13.2'); rec.stop(); } }, opts.max_s * 1000); }
    rec.ondataavailable = (ev) => { if (ev.data.size) recorder.chunks.push(ev.data); };
    rec.onstop = async () => {
      const r = recorder; recorder = null;
      r.stream.getTracks().forEach((t) => t.stop());
      $('compose-voice').textContent = 'Record voice'; $('compose-voice-state').textContent = 'sealing and uploading…';
      try { await sendVoice(r.gid, new Blob(r.chunks, { type: rec.mimeType || mime || 'audio/webm' }), Math.min(Date.now() - r.started, (opts.max_s || 1e9) * 1000), r.purpose, r.session); }
      catch (e) { notify(`voice message not sent: ${e.message || e}`); log(`✗ voice message: ${e.message || e}`, 'M§8.4'); }
      $('compose-voice-state').textContent = '';
    };
    rec.start(250);
    $('compose-voice').textContent = 'Stop and send'; $('compose-voice-state').textContent = 'recording…';
  } catch (e) { notify(`cannot record: ${e.message || e}`); }
}

/** M§8.4 rules 1–4 and M§5.6: seal under a fresh key, PUT the ciphertext to our mailbox with a signed blob-put, then
 *  send the audio content carrying the key; the deposit's manifest carries the blob without it. */
async function sendVoice(gid, blob, durationMs, purpose = 'voice-message', session = undefined) {
  const plain = await blob.arrayBuffer();
  const sealed = JSON.parse(messenger.seal_blob(b64u.encode(plain)));
  const uri = `${blobEndpoint().replace(/\/$/, '')}/${sealed.sha256}`;
  const auth = messenger.blob_put(sealed.sha256, sealed.size, now());
  const r = await fetch(uri, { method: 'PUT', headers: { Authorization: `DSIP ${auth}`, 'Content-Type': 'application/octet-stream' }, body: b64u.decode(sealed.sealed) });
  const answer = payloadOf(await r.text());
  if (!(r.status === 200 || r.status === 201) || answer.type !== 'accepted') throw new Error(`blob upload refused: ${r.status} ${answer.reason || ''}`);
  log(`blob ${sealed.sha256.slice(0, 12)}… (${sealed.size} B, ciphertext) uploaded to ${uri}: ${r.status}${answer.duplicate ? ' (already held)' : ''}`, 'M§5.6');
  const content_type = blob.type || 'audio/webm';
  lastVoice = { plain_size: plain.byteLength, sha256: sealed.sha256, size: sealed.size, content_type, duration_ms: durationMs };
  const frame = messenger.send_audio(gid, JSON.stringify({ uri, sha256: sealed.sha256, size: sealed.size, key: sealed.key, content_type }), durationMs, purpose, session, now());
  await driveMailbox([{ send: frame }]);
  log(`${purpose === 'voicemail' ? `voicemail for call ${short(session)}` : 'voice message'} sent: ${Math.round(durationMs / 1000)} s, ${content_type}, the key in the content and never on the mailbox`, 'M§8.2 · M§8.4');
}

/** Fetch and open a content's blob (M§8.4 rules 6–7): the sources the pinned rule orders (our mailbox's copy first),
 *  each verified by size and SHA-256 before it is decrypted; a source with nothing to serve is tried again as the pinned
 *  decision says (spec-gap 106). */
async function fetchBlob(gid, m, attempt = 1) {
  const id = m.object.id;
  if (media[id] && media[id].state !== 'retry') return;
  media[id] = { state: 'fetching', attempt };
  const sources = JSON.parse(messenger.blob_sources(JSON.stringify(m.object), JSON.stringify(m.blobs || null)));
  const tried = [];
  for (const uri of sources) {
    try {
      const r = await fetch(uri);
      if (!r.ok) { tried.push({ uri, status: r.status }); log(`blob source ${uri}: ${r.status}`, 'M§8.4'); continue; }
      const stored = await r.arrayBuffer();
      try {
        const plain = messenger.open_blob(JSON.stringify(m.object), b64u.encode(stored));
        const url = URL.createObjectURL(new Blob([b64u.decode(plain)], { type: m.object.blob?.content_type || 'audio/webm' }));
        media[id] = { state: 'ready', url, from: uri, size: stored.byteLength };
        log(`blob for ${short(id)} fetched from ${uri}: size and SHA-256 verified, decrypted under the content's key`, 'M§8.4 rule 7');
        renderMessages();
        return;
      } catch (why) { tried.push({ uri, status: 200, size: stored.byteLength }); log(`blob source ${uri}: ${why}`, 'M§8.4 rule 7'); }
    } catch (e) { tried.push({ uri, status: 0 }); log(`blob source ${uri}: ${e.message}`, 'M§8.4'); }
  }
  const d = JSON.parse(messenger.blob_fetch_decision(JSON.stringify(m.object), JSON.stringify(tried), attempt));
  if (d.action === 'retry') {
    const delay = Math.min(4000 << Math.min(attempt - 1, 4), 60000);
    media[id] = { state: 'retry', attempt: attempt + 1 };
    log(`blob for ${short(id)}: nothing served yet, trying again in ${delay / 1000} s (attempt ${attempt})`, 'spec-gap 106');
    setTimeout(() => fetchBlob(gid, m, attempt + 1), delay);
  } else { media[id] = { state: 'failed', why: d.reason }; log(`blob for ${short(id)} given up: ${d.reason}`, 'M§8.4'); renderMessages(); }
}

async function sendText(text) {
  if (!messenger || !activeConv || !text.trim()) return;
  try { await driveMailbox([{ send: messenger.send_text(activeConv, text.trim(), now()) }]); } catch (e) { notify(`not sent: ${e.message || e}`); }
}

/** A group conversation's name: its other members (M§7.3). */
function groupName(c) {
  const others = c.members.filter((m) => m !== identity.identity);
  return others.length ? `group: ${others.map((m) => nameOf(m) || short(m)).join(', ')}` : 'group (only you)';
}

function renderMessages() {
  const mb = mailboxOf();
  const status = !mb ? 'no mailbox: set one under Settings → Network (the operator may serve a default)'
    : !messenger ? `mailbox ${mb.uri}: messaging not started`
    : !mailboxInfo ? `mailbox ${mb.uri} (${short(mb.did)}): connecting…`
    : `mailbox ${mb.uri} (${short(mb.did)}): bound · personal group ${messenger.personal() ? 'yes' : devices.length > 1 ? 'waiting to be added by another device (M§12.3)' : 'pending'} · this device's MLS state is kept in this browser's storage`;
  $('mailbox-status').textContent = status;
  const convs = messenger ? JSON.parse(messenger.conversations(now())).filter((c) => c.kind !== 'personal') : [];
  const ul = $('conv-list');
  ul.innerHTML = convs.length ? '' : '<li class="muted small">none yet: open a contact and choose Message</li>';
  for (const c of convs) {
    const li = document.createElement('li');
    li.className = c.group === activeConv ? 'active' : '';
    li.innerHTML = '<span class="name"></span> <code class="did"></code> <span class="muted small meta"></span>';
    li.querySelector('.name').textContent = c.peer ? nameOf(c.peer) || '(unnamed)' : c.kind === 'group' ? groupName(c) : c.kind;
    li.querySelector('.did').textContent = c.peer || c.group;
    li.querySelector('.meta').textContent = `${c.members.length} identit${c.members.length === 1 ? 'y' : 'ies'}, epoch ${c.epoch}${c.pending ? `, ${c.pending} pending` : ''}${c.hub_down ? ', hub unreachable' : ''}${c.predecessors?.length ? ', continued from a group whose hub is gone' : ''}`;
    li.onclick = () => { activeConv = c.group; renderMessages(); };
    ul.append(li);
  }
  const rl = $('msg-request-list');
  const reqs = messenger ? Object.entries(JSON.parse(messenger.requests())) : [];
  rl.innerHTML = reqs.length ? '' : '<li class="muted small">none</li>';
  for (const [id, r] of reqs) { const li = document.createElement('li'); li.innerHTML = '<code class="did"></code> <span class="small purpose"></span>'; li.querySelector('.did').textContent = r.from; li.querySelector('.purpose').textContent = `“${r.purpose}” (${id})`; rl.append(li); }
  if (activeConv && !convs.some((c) => c.group === activeConv)) {
    const next = convs.find((c) => c.predecessors?.includes(activeConv));   // M§7.5: the conversation moved on
    if (next) activeConv = next.group;
  }
  const conv = convs.find((c) => c.group === activeConv);
  $('thread-title').textContent = conv ? (conv.peer ? nameOf(conv.peer) || '(unnamed)' : conv.kind === 'group' ? groupName(conv) : conv.kind) : 'no conversation open';
  // M§7.3: a group's members, each removable by any member identity; any contact not in it can be added
  const isGroup = conv?.kind === 'group';
  $('group-members').classList.toggle('hidden', !isGroup);
  if (isGroup) {
    const ml = $('group-member-list'); ml.innerHTML = '';
    for (const m of conv.members) {
      const span = document.createElement('span'); span.className = 'member';
      span.textContent = m === identity.identity ? 'you ' : `${nameOf(m) || short(m)} `;
      if (m !== identity.identity) { const b = document.createElement('button'); b.type = 'button'; b.textContent = 'Remove'; b.dataset.member = m; b.onclick = () => removeMember(conv.group, m); span.append(b); }
      ml.append(span, ' ');
    }
    const sel = $('add-member-select'); sel.innerHTML = '';
    for (const c of contacts.filter((c) => !conv.members.includes(c.did))) { const o = document.createElement('option'); o.value = c.did; o.textContent = c.name || short(c.did); sel.append(o); }
    $('btn-add-member').disabled = !sel.options.length;
    $('btn-add-member').onclick = () => sel.value && addMember(conv.group, sel.value);
  }
  $('thread-did').textContent = conv?.peer || '';
  // C§5: a recorded conversation says who records; C§9: with the record-keeper, only call records go there
  const recorders = (conv?.recorders || []).map((r) => `${r.subject === identity.identity ? 'you' : nameOf(r.subject) || short(r.subject)} (device ${short(r.device)})`);
  const keeperConv = conv && conv.peer && conv.peer === settings.record_keeper;
  $('thread-meta').textContent = conv ? `group ${conv.group} · hub ${short(conv.hub.did)} (${conv.hub.did === mb?.did ? 'our mailbox' : 'their mailbox'}) · epoch ${conv.epoch}`
    + (conv.recorded ? ` · ⏺ RECORDED by ${recorders.join(', ')} (C§5)${keeperConv ? ': your record-keeper; call records go here (C§9)' : ''}` : '') : '';
  $('thread-meta').classList.toggle('warn', !!conv?.recorded);
  // C§5: content and receipts wait until the user accepts every recorder present; a new recorder asks again
  const ask = conv && conv.recorders_pending?.length && !messenger.is_recorder();
  $('recording-ask').classList.toggle('hidden', !ask);
  $('btn-leave').classList.toggle('hidden', !conv || conv.kind === 'personal');
  if (conv) $('btn-leave').onclick = () => leaveConversation(conv.group);
  // M§7.4: any member may move the group to another hub; this client offers its own mailbox
  $('btn-move-hub').classList.toggle('hidden', !conv || conv.kind === 'personal' || conv.hub.did === mb?.did);
  if (conv) $('btn-move-hub').onclick = () => moveHub(conv.group);
  if (ask) {
    $('btn-decline-recording').onclick = () => leaveConversation(conv.group);
    $('recording-ask-text').textContent = `${conv.recorders_pending.map((r) => `${nameOf(r.subject) || short(r.subject)} records this conversation on device ${short(r.device)}`).join('; ')}. `
      + 'Nothing you write, and no receipt, is sent here until you accept. Declining is leaving the conversation (C§5, M§7).';
    $('btn-accept-recording').onclick = () => acceptRecording(conv.group);
  }
  const th = $('thread');
  th.innerHTML = '';
  const timeline = conv ? JSON.parse(messenger.timeline(conv.group)) : [];
  const thread = timeline.filter((m) => !m.call);
  // M§10.3: each identity's watermark is a content id; the seq it names is the thread's
  const marks = conv ? JSON.parse(messenger.read_marks(conv.group)) : {};
  const seqOf = (id) => thread.find((m) => m.object.id === id)?.seq ?? -1;
  const theirRead = Math.max(-1, ...Object.entries(marks).filter(([who]) => who !== identity.identity).map(([, id]) => seqOf(id)));
  // M§7.3: roster changes, each before the first message the hub ordered after it
  const roster = conv ? JSON.parse(messenger.roster_log(conv.group)) : [];
  const rosterDiv = (r) => { const d = document.createElement('div'); d.className = 'msg roster muted small'; d.textContent = rosterLine(r); d.dataset.epoch = r.epoch; return d; };
  let ri = 0;
  for (const m of timeline) {
    while (ri < roster.length && m.seq != null && m.group === roster[ri].group && roster[ri].seq != null && roster[ri].seq < m.seq) th.append(rosterDiv(roster[ri++]));
    const d = document.createElement('div');
    if (m.call) {
      // M§13.3: this identity's call events for the peer, interleaved by the pinned rule
      d.className = 'msg call';
      d.textContent = `${m.call.outcome === 'declined' ? 'Declined call' : 'Missed call'} · ${new Date(m.call.at * 1000).toLocaleTimeString()}`;
      d.dataset.session = m.call.session;
      th.append(d);
      continue;
    }
    d.className = `msg${m.mine ? ' mine' : ''}${m.from_archive ? ' archive' : ''}`;
    d.innerHTML = '<span class="who"></span><span class="text"></span><span class="seq"></span><span class="read"></span>';
    d.querySelector('.who').textContent = m.mine ? 'you' : nameOf(m.sender) || short(m.sender);
    if (m.object.kind === 'audio' && m.object.blob) {
      const id = m.object.id, st = media[id];
      const text = d.querySelector('.text');
      if (st?.state === 'ready') {
        // one player per message, kept across re-renders (replacing it mid-play aborts the playback)
        if (!st.el) {
          const a = document.createElement('audio'); a.controls = true; a.src = st.url; a.dataset.id = id;
          a.onplay = () => { if (!m.mine) driveMailbox(messenger.played(m.group, id, now())).catch(() => {}); };   // M§10.4
          st.el = a;
        }
        text.append(st.el);
      } else text.textContent = st?.state === 'failed' ? `(voice message: ${st.why})` : '(voice message, fetching…)';
      text.append(` ${Math.round((m.object.duration_ms || 0) / 1000)} s${m.object.purpose === 'voicemail' ? ` voicemail${m.object.session ? ` for call ${short(m.object.session)}` : ''}` : ''}`);
      if (!st) setTimeout(() => fetchBlob(m.group, m), 0);
    } else d.querySelector('.text').textContent = m.object.text || `(${m.object.kind})`;
    d.querySelector('.seq').textContent = m.seq == null ? 'pending' : `#${m.seq}${m.mine && m.delivered && Object.keys(m.delivered).length ? ' ✓✓' : ''}`;
    const played = m.mine && m.played && Object.keys(m.played).length ? ' · played' : '';
    d.querySelector('.read').textContent = (m.mine && m.seq != null && m.seq <= theirRead ? 'read' : '') + played;
    th.append(d);
  }
  while (ri < roster.length) th.append(rosterDiv(roster[ri++]));
  $('thread-marks').textContent = conv ? Object.entries(marks).map(([who, id]) => `${who === identity.identity ? 'you' : nameOf(who) || short(who)} read through #${seqOf(id)}`).join(' · ') : '';
  th.scrollTop = th.scrollHeight;
  const canWrite = conv && conv.may_send !== false && !messenger.is_recorder();   // C§5: a recorder never speaks; nor does content reach one not accepted
  $('compose-text').disabled = !canWrite; $('compose-send').disabled = !canWrite;
  $('compose-voice').disabled = !canWrite || !blobEndpoint();
  renderRecords();
  // M§10.3: the thread is on screen, so its last content is read; the machine decides whether a watermark goes out
  const last = [...thread].reverse().find((m) => m.seq != null && m.object.object === 'content');
  if (conv && last && !$('view-messages').classList.contains('hidden') && lastRead[conv.group] !== last.object.id) {
    lastRead[conv.group] = last.object.id;
    setTimeout(() => { if (messenger) driveMailbox(messenger.read_through(conv.group, last.object.id, now())).catch(() => {}); }, 0);
  }
}

(async () => {
  await init();
  settings = (await store.get(key('settings'))) || {};
  if (settings.tn_nodes && !settings.nodes) { settings.nodes = settings.tn_nodes; delete settings.tn_nodes; }   // stage 4's name
  try {
    const r = await fetch('config.json');
    if (r.ok) { served = await r.json(); log(`operator defaults from ${location.origin}/config.json: ${Object.keys(served).join(', ') || 'none'}`, 'spec-gap 114'); }
  } catch { /* no operator config: every setting is the person's or built in */ }
  contacts = (await store.get(key('contacts'))) || [];
  purposes = (await store.get(key('purposes'))) || {};
  links = (await store.get(key('links'))) || [];
  identity = await store.get(key('identity'));
  devices = (await store.get(key('devices'))) || [];
  revoked = (await store.get(key('revoked'))) || [];
  documents = (await store.get(key('documents'))) || {};
  hintSeq = (await store.get(key('hint_seq'))) || 0;

  const fresh = !identity;
  if (fresh) {
    identity = JSON.parse(create_identity(null, null, '', now()));
    $('welcome-did').textContent = identity.identity;
    $('welcome-device').textContent = identity.device;
    show('welcome');
    await new Promise((resolve) => {
      $('welcome-continue').onclick = async () => { identity.display_name = $('welcome-name').value.trim(); await store.set(key('identity'), identity); resolve(); };
      $('welcome-import').onclick = () => $('import-file').click();
      $('import-file').onchange = async (e) => { const f = e.target.files[0]; if (f) await importFromText(await f.text()); };
    });
  }

  if (!devices.some((d) => d.device === identity.device)) { devices.unshift({ device: identity.device, enrolled: Math.floor(now()) }); await store.set(key('devices'), devices); }
  renderHeader();
  renderSettings();
  const params = new URLSearchParams(location.search);
  if (params.get('contact') && params.get('token')) {
    // a contact link: add them, and introduce ourselves with the single-use token once the relay is bound
    const to = params.get('contact'), token = params.get('token'), name = params.get('name') || '';
    history.replaceState(null, '', location.pathname + (slot ? `?as=${slot}` : ''));
    onBound = async () => { await addContact(name, to); await sendIntroduction(to, `opened your contact link`, token); };
  }
  await startEngine();
  renderContacts();
  renderLinks();
  show('contacts');
  log(`identity ${identity.identity}`, '§7.3');
  log(`device   ${identity.device} (delegated, §7.4)`);

  for (const b of document.querySelectorAll('nav button[data-view]')) b.onclick = () => { if (!call) { show(b.dataset.view); if (b.dataset.view === 'messages') renderMessages(); } else notify('finish the call first'); };
  $('btn-log-toggle').onclick = () => $('log-panel').classList.toggle('hidden');
  $('me-did').onclick = () => navigator.clipboard?.writeText(identity.identity).then(() => notify('your DID is on the clipboard'));
  $('contact-add').onsubmit = async (e) => { e.preventDefault(); await addContact($('contact-name').value, $('contact-did').value, $('contact-number').value); $('contact-name').value = ''; $('contact-did').value = ''; $('contact-number').value = ''; };
  $('call-number').onsubmit = (e) => { e.preventDefault(); callNumber($('call-tn').value); };
  $('set-did-web-use').onclick = () => useDidWeb($('set-did-web').value);
  $('btn-did-doc').onclick = downloadDidDocument;
  $('set-binding-save').onclick = () => saveBinding($('set-binding').value);
  $('set-numbers-save').onclick = saveNumbers;
  $('btn-add-document').onclick = async () => { await addDocument($('set-document').value); $('set-document').value = ''; };
  $('introduce-form').onsubmit = (e) => { e.preventDefault(); sendIntroduction($('introduce-form').dataset.to, $('introduce-purpose').value.trim()); };
  $('introduce-cancel').onclick = () => $('introduce-form').classList.add('hidden');
  $('compose').onsubmit = async (e) => { e.preventDefault(); const t = $('compose-text').value; $('compose-text').value = ''; await sendText(t); };
  $('compose-voice').onclick = () => toggleVoice();
  $('btn-new-group').onclick = () => {
    const ul = $('group-picker-list'); ul.innerHTML = '';
    for (const c of contacts) { const li = document.createElement('li'); li.innerHTML = '<label><input type="checkbox"> <span></span></label>'; li.querySelector('input').value = c.did; li.querySelector('span').textContent = c.name || short(c.did); ul.append(li); }
    if (!contacts.length) ul.innerHTML = '<li class="muted small">no contacts yet</li>';
    $('group-picker').classList.remove('hidden');
  };
  $('btn-cancel-group').onclick = () => $('group-picker').classList.add('hidden');
  $('btn-create-group').onclick = () => {
    const dids = [...document.querySelectorAll('#group-picker-list input:checked')].map((i) => i.value);
    $('group-picker').classList.add('hidden');
    if (dids.length) createGroup(dids);
  };
  $('btn-voicemail').onclick = leaveVoicemail;
  $('btn-contact-link').onclick = newContactLink;
  $('btn-accept').onclick = () => accept(false);
  $('btn-screen').onclick = () => accept(true);
  $('btn-decline').onclick = decline;
  $('btn-hangup').onclick = hangup;
  $('btn-add-video').onclick = () => sendUpdate(false);
  $('btn-escalate').onclick = () => sendUpdate(true);
  $('btn-answer-update').onclick = answerUpdate;
  $('btn-reject-update').onclick = rejectUpdate;
  $('set-name-save').onclick = async () => { identity.display_name = $('set-name').value.trim(); await store.set(key('identity'), identity); location.reload(); };
  $('set-first-contact').onchange = async (e) => { settings.first_contact_required = e.target.checked; await saveSettings(); location.reload(); };
  $('set-record-keeper-save').onclick = () => setRecordKeeper($('set-record-keeper').value.trim());
  $('btn-become-keeper').onclick = becomeRecordKeeper;
  $('set-read-disclosed').onchange = async (e) => { settings.read_disclosed = e.target.checked; await saveSettings(); if (messenger) { messenger.set_read_disclosed(settings.read_disclosed, now()); await store.set(key('messenger'), JSON.parse(messenger.save())); } log(`read receipts ${settings.read_disclosed ? 'disclosed to the conversation' : 'kept to your own devices'}`, 'M§10.5'); };
  $('set-network-save').onclick = async () => {
    settings.relay = $('set-relay').value.trim();
    try { settings.ice = $('set-ice').value.trim() ? JSON.parse($('set-ice').value) : undefined; } catch { return alert('ICE servers must be a JSON array'); }
    settings.nodes = noneable($('set-nodes').value, true);
    settings.publish_hint = $('set-publish-hint').checked;
    const mbUri = noneable($('set-mailbox').value), mbDid = $('set-mailbox-did').value.trim();
    settings.mailbox = mbUri === null ? null : mbUri ? { uri: mbUri, did: mbDid } : undefined;
    await saveSettings(); ice = null; renderSettings(); connect(); startMessaging();
  };
  $('btn-export').onclick = exportToFile;
  $('device-add').onsubmit = async (e) => {
    e.preventDefault();
    const did = $('device-did').value.trim();
    if (!/^did:key:/.test(did)) return alert('a device DID starts with did:key:');
    if (!devices.some((d) => d.device === did)) devices.push({ device: did });
    await store.set(key('devices'), devices);
    $('device-did').value = '';
    renderDevices();
    reconcileDevices();   // M§12.3: with a mailbox, the new device joins the personal group and every conversation
  };
  $('btn-import').onclick = () => $('import-file').click();
  $('import-file').onchange = async (e) => { const f = e.target.files[0]; if (f) await importFromText(await f.text()); };

  // Test and automation surface (the headless test drives the screens through the DOM; this exposes state only).
  window.dsip = {
    identity: () => identity.identity,
    state: () => (call ? engine.state(call.sid) || 'PREPARING' : null),   // null = no call; PREPARING = media being set up, no session yet
    session: () => call?.sid || null,
    relay: () => relayInfo?.did || null,
    inboundPackets: () => (call?.media ? call.media.inboundPackets() : Promise.resolve(0)),
    remoteKinds: () => ($('remote').srcObject ? $('remote').srcObject.getTracks().map((t) => t.kind).sort() : []),
    exportIdentity: (pass) => exportIdentity(identity, pass),
    importIdentity: async (text, pass) => (await enrol(await importIdentity(text, pass))).identity,
    device: () => identity.device,
    devices: () => devices.map((d) => d.device),
    revoked: () => revoked.map((r) => r.device),
    relayText: () => $('relay-status').textContent,
    addDocument,
    didDocument: () => JSON.stringify(ownDocument()),
    useDidWeb,
    setBinding: saveBinding,
    setNumbers: async ({ gateway, nodes, policy }) => { settings.gateway = gateway === null ? null : gateway || undefined; if (nodes !== undefined) settings.nodes = nodes; settings.tn_policy = policy ? JSON.parse(policy) : undefined; await saveSettings(); renderSettings(); },
    setNetwork: async ({ relay: url, ice: servers, nodes, publish }) => {
      if (url !== undefined) settings.relay = url || undefined;
      if (servers !== undefined) settings.ice = servers || undefined;
      if (nodes !== undefined) settings.nodes = nodes;
      if (publish !== undefined) settings.publish_hint = publish;
      await saveSettings(); ice = null; renderSettings(); connect();
    },
    served: () => served,
    network: () => $('network-effective').textContent,
    iceServers,
    discover,
    callRelay: () => (call && callRelays.get(call.sid)?.url) || null,
    callRelays: () => [...callRelays.values()].map((r) => r.url),
    route: () => $('call-route').textContent,
    mediaPath: () => (call?.media ? call.media.path() : Promise.resolve(null)),
    bindingStatus,
    callNumber,
    numberLine: () => $('call-number-line').textContent,
    inNumbers: () => $('in-numbers').textContent,
    inWarning: () => $('in-tn-warning').textContent,
    downgrade: () => $('call-downgrade').textContent,
    contacts: () => contacts.map((c) => c.did),
    contactStatus: (did) => [...document.querySelectorAll('#contact-list li')].find((li) => li.querySelector('.did').textContent === did)?.querySelector('.status').textContent || null,
    requests: () => engine.requests(),
    saved: () => lastPersist,   // resolves once the latest contact-file write is in storage
    links: () => links.map((l) => l.url),
    note: () => $('call-note').textContent,
    mode: () => $('call-mode').textContent,
    // messaging (stage 6)
    mailbox: () => mailboxInfo?.did || null,
    mailboxText: () => $('mailbox-status').textContent,
    setMailbox: async (m) => { settings.mailbox = m === null ? null : m || undefined; await saveSettings(); renderSettings(); startMessaging(); },
    conversations: () => (messenger ? JSON.parse(messenger.conversations(now())) : []),
    thread: (gid) => (messenger ? JSON.parse(messenger.thread(gid || activeConv)) : []),
    activeConversation: () => activeConv,
    openConversation: (gid) => { activeConv = gid; renderMessages(); },
    messagePeer,
    sendText,
    setRecordKeeper,
    becomeRecordKeeper,
    isRecorder: () => !!messenger?.is_recorder(),
    records: () => (messenger ? JSON.parse(messenger.records()) : []),
    heldRecords: () => (messenger ? messenger.held_records() : 0),
    acceptRecording,
    leaveConversation,
    createGroup,
    addMember,
    removeMember,
    moveHub,
    rosterLog: (gid) => (messenger ? JSON.parse(messenger.roster_log(gid || activeConv)) : []),
    rosterLines: () => [...document.querySelectorAll('#thread .msg.roster')].map((d) => d.textContent),
    personalGroup: () => messenger?.personal() || null,
    messengerSaved: () => store.get(key('messenger')),
    readMarks: (gid) => (messenger ? JSON.parse(messenger.read_marks(gid || activeConv)) : {}),
    setReadDisclosed: async (v) => { settings.read_disclosed = !!v; await saveSettings(); messenger?.set_read_disclosed(!!v, now()); renderSettings(); },
    reconcileDevices,
    archiveKeys: () => (messenger ? JSON.parse(messenger.archive_keys()) : []),
    addDevice: async (did) => { if (!devices.some((d) => d.device === did)) devices.push({ device: did }); await store.set(key('devices'), devices); renderDevices(); return reconcileDevices(); },
    // voice and blobs (round 2B)
    recordVoice: async (ms) => { await toggleVoice(); await new Promise((r) => setTimeout(r, ms)); const done = new Promise((r) => { const t = setInterval(() => { if (!recorder && lastVoice) { clearInterval(t); r(); } }, 100); }); await toggleVoice(); await done; return lastVoice; },
    lastVoice: () => lastVoice,
    // voicemail and call history (round 2C)
    voicemailOffered: () => pendingVoicemail,
    leaveVoicemail: async (ms) => { await leaveVoicemail(); await new Promise((r) => setTimeout(r, ms)); lastVoice = null; await leaveVoicemail(); await until(() => lastVoice, 30000); return lastVoice; },
    calls: () => JSON.parse(messenger.calls()),
    // external join (round 2C)
    available: () => JSON.parse(messenger.available()),
    // successor groups (round 2D)
    setHubTimeout: async (s) => { settings.hub_timeout_s = s; await saveSettings(); messenger?.set_hub_timeout(s); },
    outages: () => JSON.parse(messenger.outages()),
    joinAvailable,
    timeline: (gid) => JSON.parse(messenger.timeline(gid || activeConv)),
    media: (id) => (media[id] ? { state: media[id].state, from: media[id].from, size: media[id].size, why: media[id].why } : null),
    playAudio: async (id) => { const a = document.querySelector(`audio[data-id="${id}"]`); if (!a) return false; await a.play().catch(() => {}); return true; },
    blobEndpoint,
  };
})();
