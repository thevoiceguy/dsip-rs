// Headless call-records test (Recording Profile C§9, v0.13; spec-gaps 121 and 123). Kim's identity is its
// organisation's record-keeper: her device is re-delegated with `dsip.record`, never makes a personal group (C§5),
// and opens a direct conversation with each party, since a party cannot add an identity whose devices are all
// recorders. Alice and Bob name Kim as record-keeper. Their conversation with Kim is shown as recorded and takes no
// content. Each call leg yields one `call-record`: Bob's first is held until Kim opens his conversation, then sent.
// Kim keeps four records with the outcomes C§9's order gives, and the two sides' evidence shares the frames the
// relay carried unchanged (§10.2). Kim's records survive a reload.
import { launch, person, ready, until, addContact, rowButton, placeCall, checker, dump, logOf } from './lib.mjs';

const MAILBOX_A_DID = process.env.MAILBOX_A_DID;
const check = checker();
const browser = await launch();
let kim, alice, bob;
const mailboxBound = (p) => until(p.page, (d) => window.dsip.mailbox() === d, MAILBOX_A_DID, 20000);
const convWith = (p, did) => p.page.evaluate((d) => window.dsip.conversations().find((c) => c.kind === 'direct' && c.peer === d) || null, did);
const logHas = (p, re) => until(p.page, (s) => new RegExp(s).test(document.getElementById('log').textContent), re.source, 20000);

/** Kim introduces herself to `p`, `p` grants, Kim opens the conversation (C§9: the record-keeper opens it). */
const contactsView = (p) => p.page.click('nav button[data-view=contacts]');

async function keeperOpens(p) {
  await contactsView(kim); await contactsView(p);
  await rowButton(kim, p, 'Introduce');
  await kim.page.fill('#introduce-purpose', 'Call records for Acme (C§9)');
  await kim.page.click('#introduce-form button[type=submit]');
  await until(p.page, () => window.dsip.requests().length === 1);
  await p.page.click('#request-list button:text-is("Grant")');
  await until(kim.page, (did) => window.dsip.contactStatus(did) === 'they granted you', p.did);
  await rowButton(kim, p, 'Message');
  await until(kim.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did && c.members.includes(did)), p.did, 30000);
  await until(p.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did), kim.did, 30000);
}

try {
  // 1. Kim becomes a record-keeper: re-delegated with dsip.record, no personal group
  kim = await person(browser, 'Kim');
  await mailboxBound(kim);
  await Promise.all([kim.page.waitForEvent('load'), kim.page.evaluate(() => { window.dsip.becomeRecordKeeper(); }).catch(() => {})]);
  await ready(kim.page);
  await mailboxBound(kim);
  check('Kim: her device is a recorder (delegation carries dsip.record)', await kim.page.evaluate(() => window.dsip.isRecorder()));
  await logHas(kim, /never joins its identity's personal group \(C§5\)/);
  check('Kim: no personal group for a recorder device (C§5)', !(await kim.page.evaluate(() => window.dsip.personalGroup())));

  // 2. Alice and Bob name Kim as their record-keeper; everyone knows everyone
  alice = await person(browser, 'Alice');
  bob = await person(browser, 'Bob');
  await mailboxBound(alice); await mailboxBound(bob);
  for (const p of [alice, bob]) await p.page.evaluate((d) => window.dsip.setRecordKeeper(d), kim.did);
  await addContact(alice, bob); await addContact(bob, alice);
  await addContact(kim, alice); await addContact(kim, bob);

  // 3. Kim opens the conversation with Alice only
  await keeperOpens(alice);
  const ak = await convWith(alice, kim.did);
  check('Alice: the conversation with Kim is recorded by Kim\'s device (C§5)', ak.recorded && ak.recorders.some((r) => r.subject === kim.did), JSON.stringify(ak));
  check('Alice: no content may go there (recorder not accepted, C§5)', ak.may_send === false);
  await alice.page.evaluate((g) => window.dsip.openConversation(g), ak.group);
  await alice.page.click('nav button[data-view=messages]');
  check('Alice: the composer is off in the record-keeper\'s conversation', await alice.page.isDisabled('#compose-text'));
  check('Alice: the thread says who records and why', /RECORDED by .*your record-keeper/.test(await alice.page.textContent('#thread-meta')));

  // 4. Call 1: Alice calls Bob, Bob answers, Alice hangs up. Alice's record goes out; Bob's is held.
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
  await keeperOpens(bob);
  await until(bob.page, () => window.dsip.heldRecords() === 0, null, 20000);
  check('Bob: the held record went out once the conversation existed', /1 held call record sent to the record-keeper/.test(await logOf(bob)));

  // 6. Call 2: Bob calls Alice, Alice declines
  await contactsView(alice); await contactsView(bob);
  await placeCall(bob, alice);
  await until(alice.page, () => window.dsip.state() === 'ALERTING');
  const call2 = await bob.page.evaluate(() => window.dsip.session());
  await alice.page.click('#btn-decline');
  await until(bob.page, () => window.dsip.state() === null);

  // 7. Kim holds four records, one per leg
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
} catch (e) {
  check('call records', false, e.message);
  await dump(kim, alice, bob);
}
await browser.close();
console.log(`${process.env.BROWSER || 'firefox'} call-records: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
