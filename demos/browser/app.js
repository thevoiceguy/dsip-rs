// DSIP browser endpoint — glue only. Everything normative (verification, §12 engine, payloads)
// runs inside dsip_wasm; this file owns the WebSocket, the clock, WebRTC, localStorage, and the UI.
//
// Spec: §13.2 (wss, hello first), §12 (engine), §12.12 (ICE candidates in signed `info`, ACTIVE-only),
// §14.1 (no media before a signed answer), §14.4 (screening), §16.3 (SDP as a transport binding object),
// §18.2 (display names are claims), §19.4 (first contact). Impl (spec-gap 16): SDP carriage shape.

import init, { create_identity, Endpoint } from './pkg/dsip_wasm.js';

const $ = (id) => document.getElementById(id);
const now = () => Date.now() / 1000;
const slot = new URLSearchParams(location.search).get('as') || 'me';
const short = (d) => (d && d.length > 28 ? d.slice(0, 18) + '…' + d.slice(-6) : d || '');

let ep, ws, pc, localStream;
let current = null;            // current session id
let role = null;               // 'initiator' | 'responder'
let remoteOffer = null;        // payload of the invite/update we must answer
let pendingUpdate = null;      // inbound update id awaiting our answer
let pendingLocalCandidates = [];   // ICE candidates gathered before ACTIVE (info is ACTIVE-only, §12.12)
let pendingRemoteCandidates = [];  // candidates received before setRemoteDescription
let answeredByScreening = false;

function log(line, sec = '') {
  const el = $('log');
  el.textContent += `${new Date().toLocaleTimeString()}  ${line}${sec ? '   ' + sec : ''}\n`;
  el.scrollTop = el.scrollHeight;
}

// ---------------------------------------------------------------- identity (localStorage)

function loadIdentity() {
  const key = `dsip.identity.${slot}`;
  let id = localStorage.getItem(key);
  if (!id) {
    id = create_identity(null, null, slot, now());
    localStorage.setItem(key, id);
  }
  return JSON.parse(id);
}

// ---------------------------------------------------------------- engine events

function sessionState(sid) {
  const s = JSON.parse(ep.session(sid))[sid];
  return s ? s.state : null;
}

function refreshState() {
  if (!current) return;
  const st = sessionState(current);
  $('session-id').textContent = '…' + current.slice(-8);
  $('session-state').textContent = st || '';
  $('active').classList.toggle('hidden', !(st === 'ACTIVE' || st === 'INVITING' || st === 'PROCEEDING'));
  $('btn-escalate').classList.toggle('hidden', !(answeredByScreening && role === 'responder'));
}

function refreshRequests() {
  const reqs = JSON.parse(ep.requests());
  const ul = $('request-list');
  ul.innerHTML = '';
  if (!reqs.length) { ul.innerHTML = '<li class="muted small">none</li>'; return; }
  for (const [id, identity] of reqs) {
    const li = document.createElement('li');
    li.innerHTML = `<code class="did">${short(identity)}</code> `;
    const g = document.createElement('button'); g.textContent = 'grant';
    g.onclick = () => drive(ep.local(JSON.stringify({ local: 'grant', introduction: id, id: ep.new_id(now()), scope: ['dsip.invite'], valid_until: Math.floor(now()) + 31536000 }), now()));
    const r = document.createElement('button'); r.textContent = 'reject';
    r.onclick = () => drive(ep.local(JSON.stringify({ local: 'reject_introduction', introduction: id, reason: 'user.declined' }), now()));
    li.append(g, ' ', r);
    ul.append(li);
  }
}

async function drive(eventsJson) {
  const events = JSON.parse(eventsJson);
  for (const e of events) {
    if (e.send) {
      ws.send(e.send.frame);
      log(`→ ${e.send.type.padEnd(12)} to ${short(e.send.to)}`, '§12.4');
      if (e.send.type === 'invite' || e.send.type === 'progress' || e.send.type === 'answer') current = e.send.session;
    } else if (e.received) {
      await onReceived(e.received);
    } else if (e.emission) {
      await onEmission(e.emission);
    } else if (e.rejected) {
      log(`✗ inbound rejected: ${e.rejected.code} ${e.rejected.detail}`, '§10.2');
    }
  }
  localStorage.setItem(`dsip.contacts.${slot}`, ep.contacts_json());
  refreshState();
  refreshRequests();
}

async function onReceived(r) {
  const m = r.message, p = r.payload;
  log(`← ${m.type.padEnd(12)} from ${short(r.identity)}${r.display_name ? ` "${r.display_name}"` : ''} (device ${short(m.from)})  ✓ signature · delegation · replay · schema`, '§10.2');
  if (m.type === 'invite') {
    if (sessionState(m.id) !== 'OFFERED') return; // policy rejected it (first contact) — no ring, no UI
    current = m.id; role = 'responder'; remoteOffer = p; answeredByScreening = false;
    $('in-identity').textContent = r.identity;
    $('in-name').textContent = r.display_name || '(none)';
    $('in-device').textContent = m.from;
    $('in-policy').textContent = p.policy ? 'policy: ' + Object.entries(p.policy).map(([k, v]) => `${k}=${v}`).join(', ') + ' (§16.4)' : '';
    const contacts = JSON.parse(ep.contacts_snapshot());
    const known = contacts.allow.includes(r.identity) || Object.keys(contacts.grants_issued).length > 0 || Object.keys(contacts.grants_held).length > 0;
    $('in-unknown').classList.toggle('hidden', known);
    $('incoming').classList.remove('hidden');
    // §12.4 OFFERED → ALERTING: policy admits; progress ringing is sent; the user decides
    await drive(ep.local(JSON.stringify({ local: 'alert', session: m.id, ring_timeout: 120 }), now()));
  }
  if (m.type === 'answer' && role === 'initiator' && pc) {
    const sdp = p.transports?.[0]?.sdp;
    if (sdp && !m.in_reply_to) { await pc.setRemoteDescription({ type: 'answer', sdp }); await flushRemoteCandidates(); }
    if (sdp && m.in_reply_to) { await pc.setRemoteDescription({ type: 'answer', sdp }); }
  }
  if (m.type === 'answer' && role === 'responder' && m.in_reply_to && pc) {
    const sdp = p.transports?.[0]?.sdp;
    if (sdp) await pc.setRemoteDescription({ type: 'answer', sdp });
  }
  if (m.type === 'update') {
    remoteOffer = p; pendingUpdate = m.id;
    $('btn-answer-update').classList.remove('hidden'); $('btn-reject-update').classList.remove('hidden');
  }
  if (m.type === 'info' && p.about === 'transport:webrtc' && p.data?.candidates) {
    for (const c of p.data.candidates) {
      const cand = { candidate: c.candidate, sdpMid: c.sdp_mid, sdpMLineIndex: c.sdp_m_line_index };
      if (pc && pc.remoteDescription) await pc.addIceCandidate(cand); else pendingRemoteCandidates.push(cand);
    }
  }
}

async function onEmission(e) {
  if (e.timer) { log(`⏱ ${e.name} ${e.timer}${e.seconds ? ` (${e.seconds} s)` : ''}`, '§12.9'); return; }
  if (e.media) {
    log(`♫ media ${e.media}`, '§14.1');
    if (e.media === 'start') { await flushLocalCandidates(); }
    if (e.media === 'stop') teardownMedia();
    return;
  }
  if (e.ui) {
    const fields = Object.entries(e).filter(([k]) => k !== 'ui').map(([k, v]) => `${k}=${v}`).join(' ');
    const sec = { progress: '§12.10', answered: '§14.3', offered: '§12.4', missed_call: '§12.11', ended: '§12.4', glare_retry: '§12.6',
                  update_offered: '§12.8', update_rejected: '§12.8', introduction_received: '§19.4', granted: '§19.4', introduction_rejected: '§19.4' }[e.ui] || '§12';
    log(`◆ ${e.ui} ${fields}${e.ui === 'answered' && e.answered_by === 'screening' ? '  ← SCREENING MODE (§14.4)' : ''}`, sec);
    if (e.ui === 'ended') { $('incoming').classList.add('hidden'); teardownMedia(); }
    if (e.ui === 'answered' && e.answered_by === 'screening') answeredByScreening = true;
    if (e.ui === 'answered' && e.answered_by === 'user') answeredByScreening = false;
    return;
  }
  if (e.info) { log(`ℹ info for ${e.info.about}`, '§12.12'); return; }
  if (e.drop) { log(`· dropped: ${e.drop}`); return; }
  if (e.refused) { log(`✗ refused: ${e.refused}`); return; }
  if (e.queue) { log(`queued ${e.queue.type} for ${short(e.queue.to)}`); }
}

// ---------------------------------------------------------------- WebRTC glue

function newPeerConnection() {
  pc = new RTCPeerConnection({ iceServers: [] });
  pc.onicecandidate = ({ candidate }) => {
    // §12.12: candidates ride in signed info, ACTIVE-only → buffer until media start
    const entry = candidate
      ? { candidate: candidate.candidate, sdp_mid: candidate.sdpMid, sdp_m_line_index: candidate.sdpMLineIndex }
      : null;
    pendingLocalCandidates.push(entry);
    if (current && sessionState(current) === 'ACTIVE') flushLocalCandidates();
  };
  pc.ontrack = (ev) => { $('remote').srcObject = ev.streams[0]; };
  pc.onconnectionstatechange = () => log(`webrtc: ${pc.connectionState}`, 'DTLS-SRTP');
  return pc;
}

async function flushLocalCandidates() {
  if (!current || sessionState(current) !== 'ACTIVE' || !pendingLocalCandidates.length) return;
  const batch = pendingLocalCandidates; pendingLocalCandidates = [];
  const cands = batch.filter(Boolean);
  const end = batch.some((c) => c === null);
  ep.set_info_data(JSON.stringify({ candidates: cands, end_of_candidates: end }));
  await drive(ep.local(JSON.stringify({ local: 'info', session: current }), now()));
}

async function flushRemoteCandidates() {
  for (const c of pendingRemoteCandidates) await pc.addIceCandidate(c);
  pendingRemoteCandidates = [];
}

async function getMedia(video) {
  localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video });
  $('local').srcObject = localStream;
  return localStream;
}

function teardownMedia() {
  if (pc) { pc.close(); pc = null; }
  if (localStream) { localStream.getTracks().forEach((t) => t.stop()); localStream = null; }
  $('local').srcObject = null; $('remote').srcObject = null;
  pendingLocalCandidates = []; pendingRemoteCandidates = []; remoteOffer = null; pendingUpdate = null;
  $('btn-answer-update').classList.add('hidden'); $('btn-reject-update').classList.add('hidden');
}

// ---------------------------------------------------------------- actions

async function call(video) {
  const to = $('callee').value.trim();
  if (!to) return alert('enter a callee DID');
  role = 'initiator';
  await getMedia(video);
  newPeerConnection();
  localStream.getTracks().forEach((t) => pc.addTrack(t, localStream));
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  ep.set_sdp(offer.sdp);                         // §16.3: SDP as transport binding object
  const sid = ep.new_id(now());
  await drive(ep.local(JSON.stringify({ local: 'place_call', session: sid, to }), now()));
}

async function accept(screening) {
  if (!remoteOffer) return;
  const offerSdp = remoteOffer.transports?.[0]?.sdp;
  newPeerConnection();
  if (offerSdp) await pc.setRemoteDescription({ type: 'offer', sdp: offerSdp });
  if (screening) {
    // §14.4: constrained selection — receive only; no local media exposed while screening
    pc.getTransceivers().forEach((t) => { t.direction = 'recvonly'; });
  } else {
    await getMedia(!!remoteOffer.media?.some((m) => m.type === 'video'));
    localStream.getTracks().forEach((t) => pc.addTrack(t, localStream));
  }
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  ep.set_sdp(answer.sdp);
  $('incoming').classList.add('hidden');
  await drive(ep.local(JSON.stringify({ local: 'accept', session: current, answered_by: screening ? 'screening' : 'user' }), now()));
  await flushRemoteCandidates();
}

async function sendUpdate(escalate) {
  if (!pc) return;
  if (!localStream || !localStream.getVideoTracks().length) {
    const v = await navigator.mediaDevices.getUserMedia({ video: true });
    v.getTracks().forEach((t) => { pc.addTrack(t, v); });
    if (!localStream) localStream = v; else v.getTracks().forEach((t) => localStream.addTrack(t));
    $('local').srcObject = localStream;
  }
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  ep.set_sdp(offer.sdp);
  const ev = { local: 'update', session: current, id: ep.new_id(now()) };
  if (escalate) ev.answered_by = 'user';            // §14.4 step 3
  await drive(ep.local(JSON.stringify(ev), now()));
}

async function answerUpdate() {
  if (!pendingUpdate || !pc) return;
  const sdp = remoteOffer.transports?.[0]?.sdp;
  if (sdp) await pc.setRemoteDescription({ type: 'offer', sdp });
  if (!localStream) await getMedia(true);
  const have = new Set(pc.getSenders().map((s) => s.track && s.track.kind));
  localStream.getTracks().forEach((t) => { if (!have.has(t.kind)) pc.addTrack(t, localStream); });
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  ep.set_sdp(answer.sdp);
  const id = pendingUpdate; pendingUpdate = null;
  $('btn-answer-update').classList.add('hidden'); $('btn-reject-update').classList.add('hidden');
  await drive(ep.local(JSON.stringify({ local: 'answer_update', session: current, in_reply_to: id, answered_by: 'user' }), now()));
}

async function rejectUpdate() {
  if (!pendingUpdate) return;
  const id = pendingUpdate; pendingUpdate = null;
  $('btn-answer-update').classList.add('hidden'); $('btn-reject-update').classList.add('hidden');
  await drive(ep.local(JSON.stringify({ local: 'reject_update', session: current, in_reply_to: id, reason: 'media.unsupported' }), now()));
}

// ---------------------------------------------------------------- connection

function connect() {
  const url = `wss://${location.host}/dsip`;
  ws = new WebSocket(url);
  let bound = false;
  ws.onopen = () => { ws.send(ep.hello_frame(now())); log(`→ hello        to relay (${url})`, '§13.2'); };
  ws.onmessage = async (ev) => {
    if (!bound) {
      const r = JSON.parse(ep.relay_hello(ev.data, now()));
      if (!r.ok) { log(`✗ relay hello rejected: ${r.code} — closing (anti-splicing)`, '§20.5'); ws.close(); return; }
      bound = true;
      $('relay-status').textContent = `${short(r.did)} ✓ hello bound · caps ${JSON.stringify(r.capabilities)}`;
      log(`← hello        relay ${short(r.did)} (in_reply_to matched)`, '§13.2 · §20.5');
      return;
    }
    await drive(ep.inbound(ev.data, now()));
  };
  ws.onclose = () => { $('relay-status').textContent = 'disconnected — reconnecting'; bound = false; setTimeout(connect, 2000); };
  ws.onerror = () => {};
}

// ---------------------------------------------------------------- boot

(async () => {
  await init();
  const id = loadIdentity();
  $('slot').textContent = slot;
  $('name').value = id.display_name;
  $('did-identity').textContent = id.identity;
  $('did-device').textContent = id.device;
  const firstContact = localStorage.getItem(`dsip.policy.${slot}`) === 'first-contact';
  $('first-contact').checked = firstContact;
  ep = new Endpoint(JSON.stringify(id), JSON.stringify({ first_contact_required: firstContact }), now());
  const saved = localStorage.getItem(`dsip.contacts.${slot}`);
  if (saved) ep.load_contacts(saved);
  refreshRequests();
  log(`identity ${id.identity}`, '§7.3');
  log(`device   ${id.device} (delegated, §7.4)`);

  $('save-name').onclick = () => { id.display_name = $('name').value; localStorage.setItem(`dsip.identity.${slot}`, JSON.stringify(id)); location.reload(); };
  $('first-contact').onchange = (e) => { localStorage.setItem(`dsip.policy.${slot}`, e.target.checked ? 'first-contact' : ''); location.reload(); };
  $('btn-call').onclick = () => call(false);
  $('btn-call-video').onclick = () => call(true);
  $('btn-introduce').onclick = async () => {
    const to = $('callee').value.trim(); if (!to) return;
    const purpose = prompt('purpose (≤ 280 chars, a claim):', 'Hello — may I call you?'); if (purpose === null) return;
    await drive(ep.local(JSON.stringify({ local: 'introduce', id: ep.new_id(now()), to, purpose }), now()));
  };
  $('btn-accept').onclick = () => accept(false);
  $('btn-screen').onclick = () => accept(true);
  $('btn-decline').onclick = async () => { $('incoming').classList.add('hidden'); await drive(ep.local(JSON.stringify({ local: 'decline', session: current }), now())); };
  $('btn-hangup').onclick = async () => {
    const st = sessionState(current);
    const ev = st === 'ACTIVE' ? { local: 'hangup', session: current } : { local: 'cancel', session: current };
    await drive(ep.local(JSON.stringify(ev), now()));
  };
  $('btn-add-video').onclick = () => sendUpdate(false);
  $('btn-escalate').onclick = () => sendUpdate(true);
  $('btn-answer-update').onclick = answerUpdate;
  $('btn-reject-update').onclick = rejectUpdate;

  setInterval(() => { if (ep) drive(ep.tick(now())); }, 1000);   // timers (§12.9)
  connect();
})();
