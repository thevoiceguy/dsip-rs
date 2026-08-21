// Node smoke test for the WASM endpoint: two endpoints exchange frames in memory (no relay),
// exercising verify → engine → build inside dsip_wasm. Run: node demos/browser/test.mjs
import { readFile } from 'node:fs/promises';
import init, { create_identity, Endpoint, verify_frame } from './pkg/dsip_wasm.js';

await init({ module_or_path: await readFile(new URL('./pkg/dsip_wasm_bg.wasm', import.meta.url)) });
const now = () => Date.now() / 1000;
let failures = 0;
const check = (name, ok, extra = '') => { console.log(`[${ok ? 'PASS' : 'FAIL'}] ${name} ${extra}`); if (!ok) failures++; };
const payloadOf = (frame) => JSON.parse(Buffer.from(JSON.parse(frame).payload, 'base64url').toString());

const alice = JSON.parse(create_identity(null, null, 'Alice', now()));
const bob = JSON.parse(create_identity(null, null, 'Bob', now()));
const A = new Endpoint(JSON.stringify(alice), JSON.stringify({ video: false }), now());
const B = new Endpoint(JSON.stringify(bob), JSON.stringify({}), now());

// in-memory "relay": frames from A go to B and vice versa
const box = { A: [], B: [] };
function drive(who, eventsJson) {
  const ev = JSON.parse(eventsJson);
  for (const e of ev) if (e.send) box[who === 'A' ? 'B' : 'A'].push(e.send.frame);
  return ev;
}
function pump() {
  let moved = true, all = { A: [], B: [] };
  while (moved) {
    moved = false;
    for (const who of ['A', 'B']) {
      const ep = who === 'A' ? A : B;
      while (box[who].length) { moved = true; all[who].push(...drive(who, ep.inbound(box[who].shift(), now()))); }
    }
  }
  return all;
}
const kinds = (evs) => evs.map((e) => e.send ? `send:${e.send.type}` : e.received ? `recv:${e.received.message.type}` : e.emission?.ui ? `ui:${e.emission.ui}` : e.emission?.media ? `media:${e.emission.media}` : e.rejected ? `rejected:${e.rejected.code}` : null).filter(Boolean);

// 1. call: alice → bob (identity), bob alerts and accepts
A.set_sdp('v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n');
const sid = A.new_id(now());
drive('A', A.local(JSON.stringify({ local: 'place_call', session: sid, to: bob.identity }), now()));
let r = pump();
check('bob received verified invite', kinds(r.B).includes('recv:invite') && kinds(r.B).includes('ui:offered'), JSON.stringify(kinds(r.B)));
drive('B', B.local(JSON.stringify({ local: 'alert', session: sid, ring_timeout: 60 }), now()));
B.set_sdp('v=0\r\no=- 2 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n');
drive('B', B.local(JSON.stringify({ local: 'accept', session: sid, answered_by: 'user' }), now()));
r = pump();
const ka = kinds(r.A);
check('alice: progress then answer → ACTIVE with media start', ka.includes('recv:progress') && ka.includes('recv:answer') && ka.includes('media:start'), JSON.stringify(ka));
check('alice session ACTIVE', JSON.parse(A.session(sid))[sid].state === 'ACTIVE');
check('bob session ACTIVE', JSON.parse(B.session(sid))[sid].state === 'ACTIVE');
const answerEv = r.A.find((e) => e.received?.message.type === 'answer');
check('answer carried SDP in transports[0].sdp (§16.3 binding object)', answerEv?.received.payload.transports?.[0]?.sdp?.startsWith('v=0'));

// 2. ICE candidates ride in signed info (ACTIVE-only)
A.set_info_data(JSON.stringify({ candidates: [{ candidate: 'candidate:1 1 udp 1 127.0.0.1 5000 typ host', sdp_mid: '0', sdp_m_line_index: 0 }], end_of_candidates: false }));
drive('A', A.local(JSON.stringify({ local: 'info', session: sid }), now()));
r = pump();
check('bob received info with candidates', r.B.some((e) => e.received?.message.type === 'info' && e.received.payload.data.candidates.length === 1));

// 3. renegotiation: bob adds video via update; alice answers it
B.set_sdp('v=0\r\no=- 3 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n');
const uid = B.new_id(now());
drive('B', B.local(JSON.stringify({ local: 'update', session: sid, id: uid }), now()));
r = pump();
check('alice: update offered', kinds(r.A).includes('ui:update_offered'));
A.set_sdp('v=0\r\no=- 4 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n');
drive('A', A.local(JSON.stringify({ local: 'answer_update', session: sid, in_reply_to: uid }), now()));
r = pump();
check('bob: update answered → media apply_update', kinds(r.B).includes('media:apply_update'));

// 4. hangup
drive('A', A.local(JSON.stringify({ local: 'hangup', session: sid }), now()));
r = pump();
check('bob: bye → ended', kinds(r.B).includes('ui:ended') && JSON.parse(B.session(sid))[sid].state === 'ENDED');
const probe = JSON.parse(A.local(JSON.stringify({ local: 'info', session: sid }), now()));
check('info on ended session refused', probe.some((e) => e.emission?.refused === 'invalid-state'));

// 5. standalone verifier: fresh introduction accepted, tampered frame rejected
const goodFrame = JSON.parse(B.local(JSON.stringify({ local: 'introduce', id: B.new_id(now()), to: alice.identity, purpose: 'hi' }), now())).find((e) => e.send).send.frame;
const v1 = JSON.parse(verify_frame(goodFrame, JSON.stringify({ now: Math.floor(now()) })));
check('verify_frame accepts a fresh introduction', v1.verdict === 'accept' && v1.type === 'introduction', JSON.stringify(v1).slice(0, 100));
const env = JSON.parse(goodFrame);
env.payload = env.payload.slice(0, 20) + (env.payload[20] === 'A' ? 'B' : 'A') + env.payload.slice(21);
const v2 = JSON.parse(verify_frame(JSON.stringify(env), JSON.stringify({ now: Math.floor(now()) })));
check('verify_frame rejects a tampered frame', v2.verdict === 'reject' && v2.code === 'signature-invalid', JSON.stringify(v2));

// 6. first contact in wasm
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
