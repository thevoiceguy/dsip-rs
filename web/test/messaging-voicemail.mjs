// Headless messaging test, round 2 part C: voicemail and call history (M§13). Bob's mailbox entry advertises
// voicemail (M§4.2). Alice calls Bob and hangs up while it rings: her own cancel offers no voicemail (M§13.2), Bob's
// device records a missed call in his personal group (M§13.3). Alice calls again and Bob declines: Alice is offered a
// voicemail, records it, and it reaches Bob as audio with purpose voicemail and the invite's session, end to end through
// the direct conversation. Bob's timeline interleaves both call events and the voicemail; a reload keeps them.
import { launch, person, ready, until, addContact, rowButton, checker, dump, logOf, sleep } from './lib.mjs';

const MAILBOX_A_DID = process.env.MAILBOX_A_DID;
const check = checker();
const browser = await launch();
let alice, bob, aConv, bConv;
const mailboxBound = (p, did) => until(p.page, (d) => window.dsip.mailbox() === d, did, 20000);
const personalUp = (p) => until(p.page, () => /◇ personal /.test(document.getElementById('log').textContent), null, 20000);
const convWith = (p, did) => p.page.evaluate((d) => window.dsip.conversations().find((c) => c.kind === 'direct' && c.peer === d) || null, did);
const call = async () => {
  await alice.page.click('nav button[data-view=contacts]');
  await rowButton(alice, bob, 'Call');
  // the contact list re-renders on many events; a click that lands mid-render places no call, so confirm it did
  if (!(await until(alice.page, () => window.dsip.state() !== null, null, 3000).then(() => true, () => false))) {
    console.log('  note: the Call click placed no call; clicking again');
    await rowButton(alice, bob, 'Call');
  }
  await bob.page.waitForSelector('#view-incoming:not(.hidden)', { timeout: 20000 });
  await until(bob.page, () => /◆ alert|progress|ALERTING/.test(document.getElementById('log').textContent), null, 5000).catch(() => {});
  await sleep(500);
};
try {
  // 1. Introduced, granted (dsip.invite and dsip.message), a direct conversation up
  alice = await person(browser, 'Alice');
  bob = await person(browser, 'Bob');
  await mailboxBound(alice, MAILBOX_A_DID); await mailboxBound(bob, MAILBOX_A_DID);
  await personalUp(alice); await personalUp(bob);
  await addContact(alice, bob); await addContact(bob, alice);
  await rowButton(alice, bob, 'Introduce');
  await alice.page.fill('#introduce-purpose', 'voicemail test');
  await alice.page.click('#introduce-form button[type=submit]');
  await until(bob.page, () => window.dsip.requests().length === 1);
  await bob.page.click('#request-list button:text-is("Grant")');
  await until(alice.page, (did) => window.dsip.contactStatus(did) === 'they granted you', bob.did);
  await rowButton(alice, bob, 'Message');
  await until(alice.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did && c.members.length === 2), bob.did, 30000);
  aConv = await convWith(alice, bob.did);
  await until(bob.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did), alice.did, 30000);
  bConv = await convWith(bob, alice.did);

  // 2. Alice calls and hangs up while it rings: no voicemail offer; Bob's device records a missed call
  await call();
  await alice.page.click('#btn-hangup');
  await until(bob.page, () => window.dsip.calls().length === 1, null, 20000);
  const missed = (await bob.page.evaluate(() => window.dsip.calls()))[0];
  check('Bob: a missed call event went to his personal group (M§13.3)', missed.outcome === 'missed' && missed.peer === alice.did && missed.direction === 'inbound', JSON.stringify(missed));
  await sleep(1500);
  check('Alice: her own hang-up offers no voicemail (M§13.2: only her cancel on a timer expiry does)', (await alice.page.evaluate(() => window.dsip.voicemailOffered())) === null);

  // 3. Alice calls again, Bob declines: a declined call event; Alice is offered a voicemail
  await call();
  const session = await bob.page.evaluate(() => window.dsip.state() && document.getElementById('log').textContent.match(/offered .*session=(\S+)/)?.[1]);
  await bob.page.click('#btn-decline');
  await until(bob.page, () => window.dsip.calls().length === 2, null, 20000);
  const declined = (await bob.page.evaluate(() => window.dsip.calls()))[1];
  check('Bob: his decline is recorded as a declined call (spec-gap 63)', declined.outcome === 'declined' && declined.session !== missed.session, JSON.stringify(declined));
  await until(alice.page, () => window.dsip.voicemailOffered() !== null, null, 20000);
  const offer = await alice.page.evaluate(() => window.dsip.voicemailOffered());
  check('Alice: a voicemail is offered after user.declined, up to Bob\'s advertised limit (M§13.2, M§4.2)', offer.peer === bob.did && offer.max_s === 180 && /voicemail offered .*reject user\.declined/.test(await logOf(alice)), JSON.stringify(offer));
  check('Alice: the voicemail button is shown', await alice.page.isVisible('#btn-voicemail'));

  // 4. Alice records it; it reaches Bob end to end as audio, purpose voicemail, carrying the session
  const vm = await alice.page.evaluate(() => window.dsip.leaveVoicemail(1500));
  check('Alice: the voicemail was sealed, uploaded and sent', vm && vm.size > 0 && /voicemail for call .* sent/.test(await logOf(alice)), JSON.stringify(vm));
  await until(bob.page, (g) => window.dsip.thread(g).some((m) => m.object.purpose === 'voicemail'), bConv.group, 20000);
  const got = await bob.page.evaluate((g) => window.dsip.thread(g).find((m) => m.object.purpose === 'voicemail').object, bConv.group);
  check('Bob: the voicemail is audio content with purpose voicemail, its session the declined call\'s (M§13.1, M§13.2)', got.kind === 'audio' && got.session === declined.session && got.duration_ms >= 1000 && (!session || got.session === session), JSON.stringify({ kind: got.kind, session: got.session, declined: declined.session }));
  await until(bob.page, (g) => { const m = window.dsip.thread(g).find((x) => x.object.purpose === 'voicemail'); return m && window.dsip.media(m.object.id)?.state === 'ready'; }, bConv.group, 30000);
  check('Bob: the voicemail\'s blob was fetched, verified and decrypted (M§8.4)', true);

  // 5. Bob's timeline for Alice: the missed call, the declined call, then the voicemail (M§13.3)
  await bob.page.click('nav button[data-view=messages]');
  await bob.page.evaluate((g) => window.dsip.openConversation(g), bConv.group);
  const tl = await bob.page.evaluate((g) => window.dsip.timeline(g).map((e) => (e.call ? `call:${e.call.outcome}` : `${e.object.kind}:${e.object.purpose || ''}`)), bConv.group);
  check('Bob: one timeline interleaves both calls and the voicemail in order', JSON.stringify(tl) === JSON.stringify(['call:missed', 'call:declined', 'audio:voicemail']), JSON.stringify(tl));
  check('Bob: the thread shows them', /Missed call[\s\S]*Declined call[\s\S]*voicemail for call/.test(await bob.page.textContent('#thread')), (await bob.page.textContent('#thread')).slice(0, 200));
  check('Alice: no call events of hers for a call she placed (M§13.3: callee legs only)', (await alice.page.evaluate(() => window.dsip.calls())).length === 0);

  // 6. A reload keeps the call log
  await bob.page.reload();
  await ready(bob.page);
  await mailboxBound(bob, MAILBOX_A_DID);
  const after = await bob.page.evaluate(() => window.dsip.calls().map((c) => c.outcome));
  check('Bob: after a reload the call log holds one missed and one declined call', JSON.stringify(after) === JSON.stringify(['missed', 'declined']), JSON.stringify(after));
} catch (err) {
  check.fail(`exception: ${err.message}`);
  await dump(alice, bob);
}
await browser.close();
console.log(`${process.env.BROWSER || 'firefox'} messaging-voicemail: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
