// Node smoke test for the WASM endpoint: two endpoints exchange frames in memory (no relay),
// exercising verify → engine → build inside dsip_wasm. Run: node web/test/engine.mjs
import { readFile } from 'node:fs/promises';
import init, { create_identity, Endpoint, verify_frame } from '../pkg/dsip_wasm.js';

await init({ module_or_path: await readFile(new URL('../pkg/dsip_wasm_bg.wasm', import.meta.url)) });
const now = () => Date.now() / 1000;
let failures = 0;
const check = (name, ok, extra = '') => { console.log(`[${ok ? 'PASS' : 'FAIL'}] ${name} ${extra}`); if (!ok) failures++; };
const payloadOf = (frame) => JSON.parse(Buffer.from(JSON.parse(frame).payload, 'base64url').toString());

const alice = JSON.parse(create_identity(null, null, 'Alice', now()));
const bob = JSON.parse(create_identity(null, null, 'Bob', now()));
const A = new Endpoint(JSON.stringify(alice), JSON.stringify({ video: false, seal: true }), now());
const B = new Endpoint(JSON.stringify(bob), JSON.stringify({ one_call: true }), now());
const eps = () => ({ A, B });

// in-memory "relay": frames from A go to B and vice versa. The page is the media host: what the call glue asks for
// (`media_request`) is answered at once with binding-valid SDP, as a browser's RTCPeerConnection would.
// Binding-valid SDP (WebRTC Media Binding B§2.2): one m=audio section with ICE credentials, a
// sha-256 fingerprint, a=setup, a=mid, direction, rtcp-mux and an opus rtpmap. The engine
// enforces the descriptor/SDP authority rule on inbound SDP, so placeholders do not pass.
const FP = 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99';
let sdpN = 0;
const sdp = (setup, direction = 'sendrecv') => ['v=0', `o=- ${++sdpN} 1 IN IP4 127.0.0.1`, 's=-', 't=0 0', 'a=group:BUNDLE 0',
  'm=audio 9 UDP/TLS/RTP/SAVPF 111', 'c=IN IP4 0.0.0.0', 'a=ice-ufrag:0123456789abcdef0123456789abcdef',
  'a=ice-pwd:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', `a=fingerprint:sha-256 ${FP}`,
  `a=setup:${setup}`, 'a=mid:0', `a=${direction}`, 'a=rtcp-mux', 'a=rtpmap:111 opus/48000/2'].join('\r\n') + '\r\n';
const box = { A: [], B: [] };
function drive(who, eventsJson) {
  const ev = JSON.parse(eventsJson);
  const out = [];
  for (const e of ev) {
    out.push(e);
    if (e.send) box[who === 'A' ? 'B' : 'A'].push(e.send.frame);
    const m = e.media_request;
    if (m?.kind === 'offer') out.push(...drive(who, eps()[who].media(JSON.stringify({ kind: 'offer', session: m.session, sdp: sdp('actpass') }), now())));
    if (m?.kind === 'answer') out.push(...drive(who, eps()[who].media(JSON.stringify({ kind: 'answer', session: m.session, sdp: sdp('active', m.screening ? 'recvonly' : 'sendrecv') }), now())));
  }
  return out;
}
function pump() {
  let moved = true, all = { A: [], B: [] };
  while (moved) {
    moved = false;
    for (const who of ['A', 'B']) {
      const ep = eps()[who];
      while (box[who].length) {
        const f = box[who].shift();
        // §12.7: a relay delivers the caller's answered-elsewhere cancel to the other legs only, and there are none
        if (payloadOf(f).type === 'cancel' && payloadOf(f).reason === 'session.answered-elsewhere') continue;
        moved = true; all[who].push(...drive(who, ep.inbound(f, now())));
      }
    }
  }
  return all;
}
const kinds = (evs) => evs.map((e) => e.send ? `send:${e.send.type}` : e.received ? `recv:${e.received.message.type}` : e.emission?.ui ? `ui:${e.emission.ui}`
  : e.emission?.media ? `media:${e.emission.media}` : e.rejected ? `rejected:${e.rejected.code}` : e.media_request ? `mreq:${e.media_request.kind}` : e.call ? `call:${e.call.event}` : null).filter(Boolean);

// 1. call: alice → bob through the call glue: the invite waits for the page's SDP offer; bob's client rings; the
// user's accept asks for the SDP answer; the answer starts media on both sides (§14.1, §16.3)
const placed = JSON.parse(A.place(bob.identity, JSON.stringify({}), now()));
const sid = placed.session;
check('place asks the page for an SDP offer', placed.events.some((e) => e.media_request?.kind === 'offer' && e.media_request.session === sid), JSON.stringify(placed.events));
const firstOut = placed.events.flatMap((e) => (e.media_request?.kind === 'offer' ? drive('A', A.media(JSON.stringify({ kind: 'offer', session: sid, sdp: sdp('actpass') }), now())) : []));
const inviteFrame = firstOut.find((e) => e.send?.type === 'invite')?.send.frame;
check('the invite goes out once the offer is handed back', !!inviteFrame);
check('§10.4: the invite body is sealed to bob (no media in the clear)', inviteFrame && payloadOf(inviteFrame).media === undefined && payloadOf(inviteFrame).sealed !== undefined, inviteFrame && Object.keys(payloadOf(inviteFrame)).join(','));
let r = pump();
check('bob opens the sealed invite and rings', kinds(r.B).includes('recv:invite') && kinds(r.B).includes('call:ringing') && kinds(r.B).includes('send:progress'), JSON.stringify(kinds(r.B)));
check('bob\'s invite carried the SDP after unsealing', r.B.find((e) => e.received?.message.type === 'invite')?.received.payload.transports?.[0]?.sdp?.startsWith('v=0'));
const accepted = drive('B', B.call(JSON.stringify({ command: 'accept', session: sid }), now()));
check('accept asks the page for an SDP answer to the offer', kinds(accepted).includes('mreq:answer') && kinds(accepted).includes('send:answer'), JSON.stringify(kinds(accepted)));
r = pump();
const ka = kinds(r.A);
check('alice: answer applied, media starts', ka.includes('recv:answer') && ka.includes('mreq:apply_answer') && ka.includes('mreq:start_sending'), JSON.stringify(ka));
check('alice session ACTIVE', JSON.parse(A.session(sid))[sid].state === 'ACTIVE');
check('bob session ACTIVE', JSON.parse(B.session(sid))[sid].state === 'ACTIVE');

// 2. ICE candidates ride in signed info (ACTIVE-only)
const cand = { candidate: 'candidate:1 1 udp 1 127.0.0.1 5000 typ host', sdp_mid: '0', sdp_m_line_index: 0 };
const sentInfo = drive('A', A.media(JSON.stringify({ kind: 'candidate', session: sid, candidate: cand }), now()));
check('a local candidate in an ACTIVE call goes out in a signed info', kinds(sentInfo).includes('send:info'));
r = pump();
check('bob: the candidate is handed to the page', r.B.some((e) => e.media_request?.kind === 'remote_candidates' && e.media_request.candidates.length === 1));

// 3. renegotiation: bob re-offers; alice answers it
drive('B', B.call(JSON.stringify({ command: 'update', session: sid }), now()));
r = pump();
check('alice: update offered', kinds(r.A).includes('call:update_offered'));
drive('A', A.call(JSON.stringify({ command: 'answer_update', session: sid }), now()));
r = pump();
check('bob: update answered → answer applied', kinds(r.B).includes('media:apply_update') && kinds(r.B).includes('mreq:apply_answer'), JSON.stringify(kinds(r.B)));

// 4. one call at a time: a second call to bob is declined busy and never put to the user
const D = new Endpoint(JSON.stringify(JSON.parse(create_identity(null, null, 'Dan', now()))), JSON.stringify({}), now());
const busyPlaced = JSON.parse(D.place(bob.identity, JSON.stringify({}), now()));
const busyInvite = JSON.parse(D.media(JSON.stringify({ kind: 'offer', session: busyPlaced.session, sdp: sdp('actpass') }), now())).find((e) => e.send?.type === 'invite').send.frame;
const busyOut = JSON.parse(B.inbound(busyInvite, now()));
const busyReject = busyOut.find((e) => e.send?.type === 'reject');
check('bob declines a second call user.busy, without ringing', busyReject && payloadOf(busyReject.send.frame).reason === 'user.busy' && !kinds(busyOut).includes('call:ringing'), JSON.stringify(kinds(busyOut)));
check('the first call is untouched', JSON.parse(B.session(sid))[sid].state === 'ACTIVE');

// 5. hangup
drive('A', A.call(JSON.stringify({ command: 'hangup', session: sid }), now()));
r = pump();
check('bob: bye → ended, media closed', kinds(r.B).includes('ui:ended') && kinds(r.B).includes('mreq:close') && JSON.parse(B.session(sid))[sid].state === 'ENDED', JSON.stringify(kinds(r.B)));
const probe = JSON.parse(A.local(JSON.stringify({ local: 'info', session: sid }), now()));
check('info on ended session refused', probe.some((e) => e.emission?.refused === 'invalid-state'));

// 6. standalone verifier: fresh introduction accepted, tampered frame rejected
const goodFrame = JSON.parse(B.local(JSON.stringify({ local: 'introduce', id: B.new_id(now()), to: alice.identity, purpose: 'hi' }), now())).find((e) => e.send).send.frame;
const v1 = JSON.parse(verify_frame(goodFrame, JSON.stringify({ now: Math.floor(now()) })));
check('verify_frame accepts a fresh introduction', v1.verdict === 'accept' && v1.type === 'introduction', JSON.stringify(v1).slice(0, 100));
const env = JSON.parse(goodFrame);
env.payload = env.payload.slice(0, 20) + (env.payload[20] === 'A' ? 'B' : 'A') + env.payload.slice(21);
const v2 = JSON.parse(verify_frame(JSON.stringify(env), JSON.stringify({ now: Math.floor(now()) })));
check('verify_frame rejects a tampered frame', v2.verdict === 'reject' && v2.code === 'signature-invalid', JSON.stringify(v2));

// 7. first contact in wasm (the engine's own vocabulary, beside the call glue)
const carol = JSON.parse(create_identity(null, null, 'Carol', now()));
const C = new Endpoint(JSON.stringify(carol), JSON.stringify({ first_contact_required: true }), now());
const sid2 = A.new_id(now());
let evs = JSON.parse(A.local(JSON.stringify({ local: 'place_call', session: sid2, to: carol.identity }), now()));
let cev = JSON.parse(C.inbound(evs.find((e) => e.send).send.frame, now()));
check('carol rejects ungranted invite with policy.first-contact-required', cev.some((e) => e.send?.type === 'reject' && payloadOf(e.send.frame).reason === 'policy.first-contact-required'));
const intro = JSON.parse(A.local(JSON.stringify({ local: 'introduce', id: A.new_id(now()), to: carol.identity, purpose: 'meetup' }), now())).find((e) => e.send).send.frame;
cev = JSON.parse(C.inbound(intro, now()));
check('carol: introduction lands in requests (no session)', cev.some((e) => e.emission?.ui === 'introduction_received') && JSON.parse(C.requests()).length === 1);
const [[introId]] = JSON.parse(C.requests());
const grantEv = JSON.parse(C.local(JSON.stringify({ local: 'grant', introduction: introId, id: C.new_id(now()), scope: ['dsip.invite'], valid_until: Math.floor(now()) + 3600 }), now()));
const aev = JSON.parse(A.inbound(grantEv.find((e) => e.send).send.frame, now()));
check('alice holds the grant', aev.some((e) => e.emission?.ui === 'granted') && Object.keys(JSON.parse(A.contacts_json()).grants_held).length === 1);
const sid3 = A.new_id(now());
evs = JSON.parse(A.local(JSON.stringify({ local: 'place_call', session: sid3, to: carol.identity }), now()));
check('granted invite carries the grant id', payloadOf(evs.find((e) => e.send).send.frame).grant !== undefined);
cev = JSON.parse(C.inbound(evs.find((e) => e.send).send.frame, now()));
check('granted invite is offered (rings)', cev.some((e) => e.emission?.ui === 'offered'));

console.log(`\n${failures} failure(s)`);
process.exit(failures ? 1 : 0);
