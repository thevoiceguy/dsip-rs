// DSIP reference client — the screens. Everything normative (verification, the §12 engine, payload building,
// first-contact state) runs inside dsip_wasm; this file owns the views and the one current call, and drives the
// host layer (relay socket, WebRTC, storage). No signaling decision is made here: a screen changes only when the
// engine emits.
//
// Spec: §12 (engine states shown as they are), §12.12 (ICE candidates in signed `info`, ACTIVE-only), §14.1 (no
// media before a signed answer), §14.4 (screening), §18.1 (the verification basis, never a badge), §18.2 (display
// names are claims), §19.4 (first contact), B§ (SDP in `transports[].sdp`), G§5/G§7 (PSTN caller line, downgrade).

import init, { create_identity, Endpoint, verification_basis, tel_caller_line, downgrade_summary } from './pkg/dsip_wasm.js';
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
    const status = held && issued ? 'mutual grant' : held ? 'they granted you' : issued ? 'you granted them' : 'no grant';
    li.innerHTML = `<span class="name"></span><code class="did"></code><span class="status">${status}</span>`;
    li.querySelector('.name').textContent = c.name || '(unnamed)';
    li.querySelector('.did').textContent = c.did;
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
    li.innerHTML = `<span class="name"></span><code class="did"></code>`;
    li.querySelector('.name').textContent = nameOf(who) || 'someone';
    li.querySelector('.did').textContent = who;
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
}

function renderRelay(text, state) {
  $('relay-status').textContent = text;
  $('relay-dot').className = `dot ${state}`;
}

// ---------------------------------------------------------------- persistence

async function persist() {
  await store.set(key('engine.contacts'), engine.contactsFile());
}

async function saveContacts() { await store.set(key('contacts'), contacts); renderContacts(); }

// ---------------------------------------------------------------- engine events

async function onReceived(r) {
  const m = r.message, p = r.payload;
  log(`← ${m.type.padEnd(12)} from ${short(r.identity)}${r.display_name ? ` "${r.display_name}"` : ''}  ✓ signature · delegation · replay · schema`, '§10.2');
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
  if (m.type === 'update') { call.offer = p; call.pendingUpdate = m.id; }
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
    if (e.ui === 'answered') { $('call-note').textContent = e.answered_by === 'screening' ? 'answered in screening mode: they hear you, you do not hear them (§14.4)' : ''; }
    if (e.ui === 'missed_call') notify(`Missed call from ${nameOf(call?.peer) || short(call?.peer)}`);
    if (e.ui === 'ended') { $('call-note').textContent = e.reason ? `ended: ${e.reason}` : 'ended'; endCall(); }
    if (e.ui === 'introduction_received') notify(`Introduction from ${nameOf(e.from) || short(e.from)}: see Requests`);
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

async function placeCall(to, video) {
  if (call && engine.state(call.sid) !== 'ENDED') return notify('already in a call');
  call = { sid: engine.newId(), role: 'initiator', peer: to, media: null, pendingLocal: [], pendingUpdate: null, screening: false };
  $('call-peer-name').textContent = nameOf(to) || '';
  $('call-peer-did').textContent = to;
  $('call-basis').textContent = verification_basis(to, '[]');
  $('call-note').textContent = '';
  $('call-downgrade').classList.add('hidden');
  show('call');
  try {
    call.media = newMedia();
    await call.media.capture(video);
    $('local').srcObject = call.media.localStream;
    engine.setSdp(await call.media.offer());               // B§: SDP as the transport binding object
    await engine.local({ local: 'place_call', session: call.sid, to });
  } catch (err) { notify(`cannot call: ${err.message || err}`); endCall(); }
  renderCall();
}

async function accept(screening) {
  if (!call || call.role !== 'responder') return;
  $('view-incoming').classList.add('hidden');
  $('call-peer-name').textContent = nameOf(call.peer) || '';
  $('call-peer-did').textContent = call.peer;
  $('call-basis').textContent = $('in-basis').textContent;
  $('call-note').textContent = screening ? 'screening: nothing of yours is sent (§14.4)' : '';
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
  else await engine.local({ local: 'cancel', session: call.sid });
}

async function sendUpdate(escalate) {
  if (!call?.media) return;
  await call.media.addVideo();
  $('local').srcObject = call.media.localStream;
  engine.setSdp(await call.media.offer());
  const ev = { local: 'update', session: call.sid, id: engine.newId() };
  if (escalate) { ev.answered_by = 'user'; call.screening = false; }   // §14.4 step 3
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

function endCall() {
  if (!call) return;
  call.media?.close();
  $('local').srcObject = null; $('remote').srcObject = null;
  $('view-incoming').classList.add('hidden');
  const ended = call; call = null;
  renderContacts();
  if (!$('view-call').classList.contains('hidden')) {
    $('call-state').textContent = 'ENDED';
    $('call-title').textContent = 'Call ended';
    setTimeout(() => { if (!call && !$('view-call').classList.contains('hidden')) show('contacts'); }, 1500);
  }
  return ended;
}

async function introduce(to) {
  const purpose = prompt('Why are you introducing yourself? (shown to them as a claim, up to 280 characters)', `Hello from ${identity.display_name || 'a DSIP user'}`);
  if (purpose === null) return;
  await engine.local({ local: 'introduce', id: engine.newId(), to, purpose });
  notify('introduction sent; it never rings, and silence is a valid answer');
}

// ---------------------------------------------------------------- contacts

async function addContact(name, did) {
  did = did.trim();
  if (!/^did:(key|web):/.test(did)) return notify('a DID starts with did:key: or did:web:');
  if (did === identity.identity) return notify('that is you');
  const existing = contacts.find((c) => c.did === did);
  if (existing) existing.name = name || existing.name; else contacts.push({ name: name.trim(), did });
  await saveContacts();
}

async function removeContact(did) { contacts = contacts.filter((c) => c.did !== did); await saveContacts(); }

// ---------------------------------------------------------------- identity and settings

async function exportToFile() {
  const pass = prompt('Choose a passphrase for the identity file (at least 8 characters). Without it the file is useless; without the file the identity is unrecoverable.');
  if (pass === null) return;
  try {
    const text = await exportIdentity(identity, pass);
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
    const id = await importIdentity(text, pass);
    await store.set(key('identity'), id);
    await store.del(key('engine.contacts'));
    location.reload();
  } catch (err) { alert(err.message); }
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
      renderRelay(`relay ${short(r.did)}`, 'ok');
      $('relay-caps').textContent = `relay ${r.did}: ${JSON.stringify(r.capabilities)}`;
      log(`← hello        relay ${short(r.did)} bound (in_reply_to matched)`, '§13.2 · §20.5');
    },
    refused: (r) => { renderRelay(`relay hello refused: ${r.code}`, 'bad'); log(`✗ relay hello rejected: ${r.code} (anti-splicing)`, '§20.5'); },
    frame: (text) => engine.inbound(text),
    closed: () => { renderRelay('disconnected, reconnecting…', 'bad'); },
    dropped: (f) => log(`✗ not connected: a ${JSON.parse(f).type || 'frame'} was not sent`),
  }, now);
  relay.connect();
}

// ---------------------------------------------------------------- boot

async function startEngine() {
  engine = new Engine(Endpoint, identity, { first_contact_required: !!settings.first_contact_required }, now);
  engine.loadContactsFile(await store.get(key('engine.contacts')));
  engine.on = {
    send: (frame, meta) => { relay.send(frame); log(`→ ${meta.type.padEnd(12)} to ${short(meta.to)}`, '§12.4'); },
    received: onReceived,
    emission: onEmission,
    rejected: (code, detail) => log(`✗ inbound rejected: ${code} ${detail || ''}`, '§10.2'),
    changed: () => { persist(); renderContacts(); renderCall(); },
  };
  engine.startTimers();
  connect();
}

(async () => {
  await init();
  settings = (await store.get(key('settings'))) || {};
  contacts = (await store.get(key('contacts'))) || [];
  identity = await store.get(key('identity'));

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

  renderHeader();
  renderSettings();
  await startEngine();
  renderContacts();
  show('contacts');
  log(`identity ${identity.identity}`, '§7.3');
  log(`device   ${identity.device} (delegated, §7.4)`);

  for (const b of document.querySelectorAll('nav button[data-view]')) b.onclick = () => { if (!call) show(b.dataset.view); else notify('finish the call first'); };
  $('btn-log-toggle').onclick = () => $('log-panel').classList.toggle('hidden');
  $('me-did').onclick = () => navigator.clipboard?.writeText(identity.identity).then(() => notify('your DID is on the clipboard'));
  $('contact-add').onsubmit = async (e) => { e.preventDefault(); await addContact($('contact-name').value, $('contact-did').value); $('contact-name').value = ''; $('contact-did').value = ''; };
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
  $('btn-import').onclick = () => $('import-file').click();
  $('import-file').onchange = async (e) => { const f = e.target.files[0]; if (f) await importFromText(await f.text()); };

  // Test and automation surface (the headless test drives the screens through the DOM; this exposes state only).
  window.dsip = {
    identity: () => identity.identity,
    state: () => (call ? engine.state(call.sid) : null),
    session: () => call?.sid || null,
    relay: () => relayInfo?.did || null,
    inboundPackets: () => (call?.media ? call.media.inboundPackets() : Promise.resolve(0)),
    exportIdentity: (pass) => exportIdentity(identity, pass),
    importIdentity: async (text, pass) => { const id = await importIdentity(text, pass); await store.set(key('identity'), id); await store.del(key('engine.contacts')); return id.identity; },
    contacts: () => contacts.map((c) => c.did),
  };
})();
