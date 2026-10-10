// DSIP reference client — the screens. Everything normative (verification, the §12 engine, payload building,
// first-contact state) runs inside dsip_wasm; this file owns the views and the one current call, and drives the
// host layer (relay socket, WebRTC, storage). No signaling decision is made here: a screen changes only when the
// engine emits.
//
// Spec: §12 (engine states shown as they are), §12.12 (ICE candidates in signed `info`, ACTIVE-only), §14.1 (no
// media before a signed answer), §14.4 (screening), §18.1 (the verification basis, never a badge), §18.2 (display
// names are claims), §19.4 (first contact), B§ (SDP in `transports[].sdp`), G§5/G§7 (PSTN caller line, downgrade),
// N§4 (a caller's bound number, checked by `check_claim`), N§4.1 (`tel:` through a gateway as `destination`), N§5
// (a number that moved), N§6 (number lookup on the nodes in Settings).

import init, { create_identity, revocation_frame, rehome, did_document, check_claim, identity_change, tn_select, Endpoint, verification_basis, tel_caller_line, downgrade_summary } from './pkg/dsip_wasm.js';
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

function renderContacts() {
  const ul = $('contact-list');
  ul.innerHTML = '';
  if (!contacts.length) ul.innerHTML = '<li class="muted small">no contacts yet: paste a DID above</li>';
  const file = JSON.parse(engine.contactsFile());     // grants by id → {identity, scope, valid_until}
  for (const c of contacts) {
    const li = document.createElement('li');
    const held = Object.values(file.grants_held || {}).some((g) => g.identity === c.did);
    const issued = Object.values(file.grants_issued || {}).some((g) => g.identity === c.did);
    const pending = Object.values(file.pending_sent || {}).includes(c.did);
    const asked = Object.values(file.requests || {}).some(([who]) => who === c.did);
    const status = held && issued ? 'mutual grant' : held ? 'they granted you' : issued ? 'you granted them'
      : asked ? 'wants to connect: see Requests' : pending ? 'introduction sent, waiting' : 'no grant';
    li.innerHTML = `<span class="name"></span><code class="did"></code><span class="muted small num"></span><span class="status">${status}</span>`;
    li.querySelector('.name').textContent = c.name || '(unnamed)';
    li.querySelector('.did').textContent = c.did;
    li.querySelector('.num').textContent = (c.numbers || []).join(' ');
    const b = (text, cls, fn) => { const x = document.createElement('button'); x.textContent = text; if (cls) x.className = cls; x.onclick = fn; return x; };
    li.append(b('Call', 'primary', () => placeCall(c.did, false)), b('Video', '', () => placeCall(c.did, true)),
      b('Introduce', '', () => introduce(c.did)), b('Remove', 'ghost', () => removeContact(c.did)));
    ul.append(li);
  }
  const reqs = engine.requests();
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
    g.onclick = () => engine.local({ local: 'grant', introduction: id, id: engine.newId(), scope: ['dsip.invite'], valid_until: Math.floor(now()) + 31536000 });
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
  $('set-relay').value = settings.relay || '';
  $('set-ice').value = settings.ice ? JSON.stringify(settings.ice) : '';
  const web = identity.identity.startsWith('did:web:');
  $('set-did-web').value = web ? identity.identity : '';
  $('did-web-host').classList.toggle('hidden', !web);
  if (web) $('did-web-url').textContent = didWebUrl(identity.identity);
  $('set-binding').value = settings.binding || '';
  $('binding-status').textContent = bindingStatus();
  $('set-gateway').value = settings.gateway || '';
  $('set-tn-nodes').value = (settings.tn_nodes || []).join(', ');
  $('set-tn-policy').value = settings.tn_policy ? JSON.stringify(settings.tn_policy) : '';
  renderDevices();
  renderDocuments();
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
  settings.gateway = $('set-gateway').value.trim() || undefined;
  settings.tn_nodes = $('set-tn-nodes').value.split(/[\s,]+/).filter(Boolean);
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

async function persist() {
  await store.set(key('engine.contacts'), engine.contactsFile());
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
      const out = JSON.parse(check_claim(JSON.stringify(c), r.identity, JSON.stringify(documents[r.identity] ?? null), now(), JSON.stringify(settings.tn_policy || {})));
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
      const refused = e.reason === 'policy.first-contact-required' && peer;
      // §12.7: a forked invite answered on another device ends this leg; §12.11: never a missed call
      const elsewhere = e.reason === 'session.answered-elsewhere';
      const noRoute = e.reason === 'identity.unknown' && call?.destination;
      $('call-note').textContent = refused ? 'They require an introduction before calls (§19.4). Introduce yourself; once they grant you, call again.'
        : elsewhere ? 'answered on another of your devices (§12.7); not a missed call'
        : noRoute ? `${call.destination}: the gateway found no identity for that number and no route (identity.unknown, N§6.1)`
        : e.reason ? `ended: ${e.reason}` : 'ended';
      endCall(refused);
      if (refused) { $('btn-introduce-after').classList.remove('hidden'); $('btn-introduce-after').onclick = () => introduce(peer); }
    }
    if (e.ui === 'introduction_received' && e.token) { notify(`${short(e.from)} used your contact link: granted`); if (!contacts.some((c) => c.did === e.from)) await addContact('', e.from); }
    else if (e.ui === 'introduction_received') notify(`Introduction from ${nameOf(e.from) || short(e.from)}: see Requests`);
    if (e.ui === 'introduction_rejected') notify(`an introduction of yours was declined${e.reason ? ` (${e.reason})` : ''}`);
    if (e.ui === 'granted') notify(`${nameOf(e.by) || short(e.by)} granted you contact`);
    return;
  }
  if (e.info) { log(`ℹ info for ${e.info.about}`, '§12.12'); return; }
  if (e.drop) { log(`· dropped: ${e.drop}`); return; }
  if (e.refused) { log(`✗ refused: ${e.refused}`); notify(`Refused: ${e.refused}`); return; }
  if (e.queue) log(`queued ${e.queue.type} for ${short(e.queue.to)}`);
}

function notify(text) { $('call-note').textContent = text; log(text); }

// ---------------------------------------------------------------- calls

function newMedia() {
  return new Media(settings.ice || [], {
    candidate: (entry) => { call.pendingLocal.push(entry); if (engine.state(call.sid) === 'ACTIVE') flushLocalCandidates(); },
    track: (stream) => { $('remote').srcObject = stream; },
    state: (s) => { log(`webrtc: ${s}`, 'B§'); if (call) $('call-note').textContent = s === 'connected' ? 'media connected (DTLS-SRTP)' : s === 'failed' ? 'media failed: check ICE servers in Settings' : $('call-note').textContent; },
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
  call = { sid: engine.newId(), role: 'initiator', peer: to, destination, media: null, pendingLocal: [], pendingUpdate: null, screening: false };
  $('call-peer-name').textContent = nameOf(to) || '';
  $('call-peer-did').textContent = to;
  $('call-basis').textContent = verification_basis(to, '[]');
  const lines = [];
  if (destination) lines.push(`to ${destination} through the gateway ${short(to)}: the number is the invite's destination (N§4.1)`);
  if (settings.binding) lines.push(`presenting ${bindingNumber()} with its binding (N§4)`);
  $('call-number-line').textContent = lines.join(' · ');
  $('call-number-line').classList.toggle('hidden', !lines.length);
  $('call-note').textContent = ''; $('call-mode').textContent = '';
  $('call-downgrade').classList.add('hidden');
  $('btn-introduce-after').classList.add('hidden');
  show('call');
  try {
    call.media = newMedia();
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
  const nodes = settings.tn_nodes || [];
  if (nodes.length) {
    const bindings = [];
    for (const n of nodes) {
      try {
        const r = await fetch(`${n.replace(/\/$/, '')}/dsip/v1/tn/${encodeURIComponent(tn)}`);
        if (r.ok) for (const b of (await r.json()).bindings || []) if (!bindings.includes(b)) bindings.push(b);
        log(`number ${tn}: ${r.ok ? `${bindings.length} binding(s)` : `${r.status}`} from ${n} (hints tier)`, 'N§6');
      } catch (e) { log(`number ${tn}: ${n} did not answer (${e.message})`, 'N§6'); }
    }
    const sel = JSON.parse(tn_select(tn, JSON.stringify(bindings), JSON.stringify(documents), now(), JSON.stringify(settings.tn_policy || {})));
    if (sel) {
      log(`number ${tn} → ${sel.did}${sel.attested_by ? ` (attested by ${sel.attested_by})` : ''}${sel.others.length ? `; also claimed by ${sel.others.join(', ')}` : ''}`, 'N§6 · N§7');
      return placeCall(sel.did, false);
    }
    log(`number ${tn}: no binding verifies`, 'N§6');
  }
  if (!settings.gateway) return notify(nodes.length ? `${tn} resolves to no identity, and no gateway is set in Settings` : 'calling a number needs number nodes or a gateway in Settings');
  log(`number ${tn} → PSTN through gateway ${short(settings.gateway)}, as the invite's destination`, 'N§4.1');
  return placeCall(settings.gateway, false, `tel:${tn}`);
}

async function accept(screening) {
  if (!call || call.role !== 'responder') return;
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
    call.media = newMedia();
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
  await engine.local({ local: 'decline', session: call.sid });
  endCall();
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

function endCall(stay = false) {
  if (!call) return;
  call.media?.close();
  $('local').srcObject = null; $('remote').srcObject = null;
  $('view-incoming').classList.add('hidden');
  const ended = call; call = null;
  renderContacts();
  if (!$('view-call').classList.contains('hidden')) {
    $('call-state').textContent = 'ENDED';
    $('call-title').textContent = 'Call ended';
    if (!stay) setTimeout(() => { if (!call && !$('view-call').classList.contains('hidden')) show('contacts'); }, 1500);
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
  await engine.local(ev);
  $('introduce-form').classList.add('hidden');
  notify('introduction sent; it never rings, and silence is a valid answer');
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

async function saveSettings() { await store.set(key('settings'), settings); }

// ---------------------------------------------------------------- relay

function relayUrl() { return settings.relay || `wss://${location.host}/dsip`; }

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
      relay.send(frame); log(`→ ${meta.type.padEnd(12)} to ${short(meta.to)}`, '§12.4');
      if (meta.type === 'reject' && payloadOf(frame).reason === 'policy.first-contact-required') log(`refused a call from ${short(meta.to)} without ringing: first contact required`, '§19.4');
    },
    received: onReceived,
    emission: onEmission,
    rejected: (code, detail) => log(`✗ inbound rejected: ${code} ${detail || ''}`, '§10.2'),
    changed: () => { persist(); renderContacts(); renderCall(); renderLinks(); },
  };
  engine.startTimers();
  connect();
}

(async () => {
  await init();
  settings = (await store.get(key('settings'))) || {};
  contacts = (await store.get(key('contacts'))) || [];
  purposes = (await store.get(key('purposes'))) || {};
  links = (await store.get(key('links'))) || [];
  identity = await store.get(key('identity'));
  devices = (await store.get(key('devices'))) || [];
  revoked = (await store.get(key('revoked'))) || [];
  documents = (await store.get(key('documents'))) || {};

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

  for (const b of document.querySelectorAll('nav button[data-view]')) b.onclick = () => { if (!call) show(b.dataset.view); else notify('finish the call first'); };
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
  $('set-network-save').onclick = async () => {
    settings.relay = $('set-relay').value.trim();
    try { settings.ice = $('set-ice').value.trim() ? JSON.parse($('set-ice').value) : undefined; } catch { return alert('ICE servers must be a JSON array'); }
    await saveSettings(); connect();
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
    setNumbers: async ({ gateway, nodes, policy }) => { settings.gateway = gateway || undefined; settings.tn_nodes = nodes || []; settings.tn_policy = policy ? JSON.parse(policy) : undefined; await saveSettings(); renderSettings(); },
    bindingStatus,
    callNumber,
    numberLine: () => $('call-number-line').textContent,
    inNumbers: () => $('in-numbers').textContent,
    inWarning: () => $('in-tn-warning').textContent,
    downgrade: () => $('call-downgrade').textContent,
    contacts: () => contacts.map((c) => c.did),
    contactStatus: (did) => [...document.querySelectorAll('#contact-list li')].find((li) => li.querySelector('.did').textContent === did)?.querySelector('.status').textContent || null,
    requests: () => engine.requests(),
    links: () => links.map((l) => l.url),
    note: () => $('call-note').textContent,
    mode: () => $('call-mode').textContent,
  };
})();
