// Headless call-records test (Recording Profile C§9, v0.13; spec-gaps 121 and 123; C§5 acceptance). Kim's identity is its
// organisation's record-keeper: her device is re-delegated with `dsip.record`, never makes a personal group (C§5),
// and opens a direct conversation with each party, since a party cannot add an identity whose devices are all
// recorders. Alice and Bob name Kim as record-keeper. Their conversation with Kim is shown as recorded and takes no
// content. Each call leg yields one `call-record`: Bob's first is held until Kim opens his conversation, then sent.
// Kim keeps four records with the outcomes C§9's order gives, and the two sides' evidence shares the frames the
// relay carried unchanged (§10.2). Kim's records survive a reload.
import { readFileSync } from 'node:fs';
import { launch, person, ready, until, addContact, rowButton, placeCall, checker, dump, submit } from './lib.mjs';

const MAILBOX_A_DID = process.env.MAILBOX_A_DID;
const check = checker();
const browser = await launch();
let kim, alice, bob;
const mailboxBound = (p) => until(p.page, (d) => window.dsip.mailbox() === d, MAILBOX_A_DID, 20000);
const convWith = (p, did) => p.page.evaluate((d) => window.dsip.conversations().find((c) => c.kind === 'direct' && c.peer === d) || null, did);
const logHas = (p, re) => until(p.page, (s) => new RegExp(s).test(document.getElementById('log').textContent), re.source, 20000);

/** Kim introduces herself to `p`, `p` grants, Kim opens the conversation (C§9: the record-keeper opens it). */
// diagnostics for a failure: page errors (a wasm panic shows here), console errors, and the step reached
const errors = [];
let step = 'start';
const watch = (p) => {
  p.page.on('pageerror', (e) => errors.push(`${p.name} pageerror: ${e.message}`));
  p.page.on('console', (m) => { if (m.type() === 'error') errors.push(`${p.name} console: ${m.text().slice(0, 300)}`); });
  return p;
};
const contactsView = (p) => p.page.click('nav button[data-view=contacts]');

async function keeperOpens(p) {
  await contactsView(kim); await contactsView(p);
  await rowButton(kim, p, 'Introduce');
  await kim.page.fill('#introduce-purpose', 'Call records for Acme (C§9)');
  await submit(kim.page, 'introduce-form');
  await until(p.page, () => window.dsip.requests().length === 1);
  await p.page.click('#request-list button:text-is("Grant")');
  await until(kim.page, (did) => window.dsip.contactStatus(did) === 'they granted you', p.did);
  await rowButton(kim, p, 'Message');
  await until(kim.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did && c.members.includes(did)), p.did, 30000);
  await until(p.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did), kim.did, 30000);
}

try {
  // 1. Kim becomes a record-keeper: re-delegated with dsip.record, no personal group
  step = '1 Kim becomes a record-keeper';
  kim = watch(await person(browser, 'Kim'));
  await mailboxBound(kim);
  // her first bind made her personal group: becoming a recorder must leave it behind (C§5), whenever the mailbox answers
  await until(kim.page, () => !!window.dsip.personalGroup(), null, 20000);
  await Promise.all([kim.page.waitForEvent('load'), kim.page.evaluate(() => { window.dsip.becomeRecordKeeper(); }).catch(() => {})]);
  await ready(kim.page);
  await mailboxBound(kim);
  check('Kim: her device is a recorder (delegation carries dsip.record)', await kim.page.evaluate(() => window.dsip.isRecorder()));
  await logHas(kim, /never joins its identity's personal group \(C§5\)/);
  check('Kim: no personal group for a recorder device (C§5)', !(await kim.page.evaluate(() => window.dsip.personalGroup())));

  // 2. Alice and Bob name Kim as their record-keeper; everyone knows everyone
  step = '2 parties name Kim';
  alice = watch(await person(browser, 'Alice'));
  bob = watch(await person(browser, 'Bob'));
  await mailboxBound(alice); await mailboxBound(bob);
  for (const p of [alice, bob]) await p.page.evaluate((d) => window.dsip.setRecordKeeper(d), kim.did);
  step = '2 contacts';
  await addContact(alice, bob); await addContact(bob, alice);
  await addContact(kim, alice); await addContact(kim, bob);

  // 3. Kim opens the conversation with Alice only
  step = '3 Kim opens Alice';
  await keeperOpens(alice);
  const ak = await convWith(alice, kim.did);
  check('Alice: the conversation with Kim is recorded by Kim\'s device (C§5)', ak.recorded && ak.recorders.some((r) => r.subject === kim.did), JSON.stringify(ak));
  check('Alice: no content may go there (recorder not accepted, C§5)', ak.may_send === false);
  await alice.page.evaluate((g) => window.dsip.openConversation(g), ak.group);
  await alice.page.click('nav button[data-view=messages]');
  check('Alice: the composer is off in the record-keeper\'s conversation', await alice.page.isDisabled('#compose-text'));
  check('Alice: the thread says who records and why', /RECORDED by .*your record-keeper/.test(await alice.page.textContent('#thread-meta')));

  // 4. Call 1: Alice calls Bob, Bob answers, Alice hangs up. Alice's record goes out; Bob's is held.
  step = '4 call 1';
  await contactsView(alice); await contactsView(bob);
  await placeCall(alice, bob);
  await until(bob.page, () => window.dsip.state() === 'ALERTING');
  await bob.page.click('#btn-accept');
  await until(alice.page, () => window.dsip.state() === 'ACTIVE');
  await until(bob.page, () => window.dsip.state() === 'ACTIVE');
  const call1 = await alice.page.evaluate(() => window.dsip.session());
  await alice.page.click('#btn-hangup');
  await until(alice.page, () => window.dsip.state() === null);
  await until(bob.page, () => window.dsip.state() === null);
  await logHas(alice, /call record for .*: answered, ended local.*sent to the record-keeper/);
  check('Alice: record for call 1 sent (answered, ended here)', true);
  await logHas(bob, /call record for .*: answered, ended remote.*held \(1\)/);
  check('Bob: record for call 1 held: Kim has not opened his conversation (C§9, spec-gap 123)', (await bob.page.evaluate(() => window.dsip.heldRecords())) === 1);

  // 5. Kim opens Bob's conversation: the held record goes out
  step = '5 Kim opens Bob';
  await keeperOpens(bob);
  // the log line follows the frame's hand-off to the mailbox, after the record has left the held list
  await logHas(bob, /1 held call record sent to the record-keeper/);
  check('Bob: the held record went out once the conversation existed', (await bob.page.evaluate(() => window.dsip.heldRecords())) === 0);

  // 6. Call 2: Bob calls Alice, Alice declines
  step = '6 call 2';
  await contactsView(alice); await contactsView(bob);
  await placeCall(bob, alice);
  await until(alice.page, () => window.dsip.state() === 'ALERTING');
  const call2 = await bob.page.evaluate(() => window.dsip.session());
  await alice.page.click('#btn-decline');
  await until(bob.page, () => window.dsip.state() === null);

  // 7. Kim holds four records, one per leg
  step = '7 four records at Kim';
  await until(kim.page, () => window.dsip.records().length === 4, null, 30000);
  const recs = await kim.page.evaluate(() => window.dsip.records());
  const rec = (from, sid) => recs.find((r) => r.from === from && r.record.session === sid)?.record;
  const [a1, b1, a2, b2] = [rec(alice.did, call1), rec(bob.did, call1), rec(alice.did, call2), rec(bob.did, call2)];
  check('Kim: four records, one per leg of each party', a1 && b1 && a2 && b2, JSON.stringify(recs.map((r) => [r.from, r.record.session, r.record.outcome])));
  check('call 1, Alice: outbound, answered, ended by her, answered_at between invite and end',
    a1.direction === 'outbound' && a1.outcome === 'answered' && a1.ended_by === 'local' && a1.invited_at <= a1.answered_at && a1.answered_at <= a1.ended_at, JSON.stringify(a1));
  check('call 1, Bob: inbound, answered, ended by the other side', b1.direction === 'inbound' && b1.outcome === 'answered' && b1.ended_by === 'remote', JSON.stringify(b1));
  check('call 1: media from the applied answer', a1.media?.includes('audio') && b1.media?.includes('audio'));
  check('call 2, Alice: inbound, declined here (user.declined)', a2.direction === 'inbound' && a2.outcome === 'declined' && a2.ended_by === 'local' && a2.reason === 'user.declined' && !a2.answered_at, JSON.stringify(a2));
  check('call 2, Bob: outbound, declined by the callee', b2.direction === 'outbound' && b2.outcome === 'declined' && b2.ended_by === 'remote', JSON.stringify(b2));
  check('each record names the device that sent it (the MLS sender leaf, C§9)',
    recs.every((r) => r.record.device === r.device) && a1.device === await alice.page.evaluate(() => window.dsip.device()));
  const shared = a1.evidence.filter((h) => b1.evidence.includes(h));
  check('evidence: the two sides\' hashes of call 1 share the frames the relay carried unchanged (§10.2)', shared.length >= 3, `${shared.length} of ${a1.evidence.length}/${b1.evidence.length}`);
  check('records name the relay the leg used', a1.relay && a1.relay === b1.relay, `${a1.relay} ${b1.relay}`);

  // 8. Kim's records list, and after a reload
  await kim.page.click('nav button[data-view=messages]');
  check('Kim: the records list shows each leg', (await kim.page.locator('#record-list li.record').count()) === 4);
  await kim.page.reload();
  await ready(kim.page);
  await until(kim.page, () => window.dsip.records().length === 4, null, 20000);
  check('Kim: the records survive a reload', true);

  // 9. C§5 acceptance: Alice accepts Kim's recorder; the acceptance goes to her personal group; content may then go
  //    to the conversation, and Kim's recorder device receives it; the acceptance survives a reload
  step = '9 Alice accepts the recording';
  await alice.page.click('nav button[data-view=messages]');
  await alice.page.evaluate((g) => window.dsip.openConversation(g), ak.group);
  check('Alice: asked to accept Kim\'s recorder before writing (C§5)', await alice.page.isVisible('#btn-accept-recording')
    && /records this conversation on device/.test(await alice.page.textContent('#recording-ask-text')));
  await alice.page.click('#btn-accept-recording');
  await logHas(alice, /recording accepted: .*through the personal group/);
  await until(alice.page, (g) => window.dsip.conversations().find((c) => c.group === g)?.may_send === true, ak.group);
  check('Alice: accepted; the conversation takes content now', !(await alice.page.isDisabled('#compose-text'))
    && !(await alice.page.isVisible('#btn-accept-recording')));
  await alice.page.fill('#compose-text', 'hello Kim, recorded and accepted');
  await alice.page.click('#compose-send');
  await until(kim.page, (g) => window.dsip.thread(g).some((m) => m.object.text === 'hello Kim, recorded and accepted'),
    (await convWith(kim, alice.did)).group, 20000);
  check('Kim: her recorder device received the accepted content', true);
  await alice.page.reload();
  await ready(alice.page);
  await until(alice.page, (g) => window.dsip.conversations().some((c) => c.group === g), ak.group, 20000);
  const after = (await alice.page.evaluate(() => window.dsip.conversations())).find((c) => c.group === ak.group);
  check('Alice: the acceptance survives a reload', after.may_send === true && after.recorders_pending.length === 0, JSON.stringify(after.recorders_pending));

  // 10. Declining is leaving (C§5, M§7.3): Bob leaves Kim's conversation; his device proposes the removal of his
  //     leaf, Kim's device commits it, and Bob's device finds itself removed
  step = '10 Bob declines by leaving';
  const bk = await convWith(bob, kim.did);
  await bob.page.click('nav button[data-view=messages]');
  await bob.page.evaluate((g) => window.dsip.openConversation(g), bk.group);
  check('Bob: asked about Kim\'s recorder, with a way to decline', await bob.page.isVisible('#btn-decline-recording'));
  await bob.page.click('#btn-decline-recording');
  await logHas(bob, /left .*: the removal of this identity's 1 leaf\(s\) proposed/);
  check('Bob: the conversation is no longer listed once he leaves', !(await convWith(bob, kim.did)));
  await logHas(kim, /◇ leave_committing .*identity=/);
  check('Kim: her device committed Bob\'s leave (MLS forbids him committing it)', true);
  await until(kim.page, (d) => !window.dsip.conversations().find((c) => c.peer === d)?.members.includes(d), bob.did, 20000);
  check('Kim: Bob is no longer a member', true);
  await logHas(bob, /◇ removed /);
  check('Bob: his device processed the commit removing it (M§7.3)', true);
} catch (e) {
  check('call records', false, `at step ${step}: ${e.message}`);
  for (const l of errors) console.log('  ' + l);
  await dump(kim, alice, bob);
  if (kim) console.log('Kim records:', JSON.stringify(await kim.page.evaluate(() => window.dsip.records().map((r) => [r.from, r.record.session, r.record.outcome])).catch(() => null)));
  // the hub's side of it: Kim's bindings, the hints it resolved and the fan-out it stored
  if (process.env.FIXTURE) for (const l of readFileSync(`${process.env.FIXTURE}/mbx-a.log`, 'utf8').split('\n').slice(-40)) console.log('  mbx-a ' + l.replace(/\x1b\[[0-9;]*m/g, ''));
}
if (errors.length && !check.failures()) for (const l of errors) console.log('  (passed, but) ' + l);
await browser.close();
console.log(`${process.env.BROWSER || 'firefox'} call-records: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
