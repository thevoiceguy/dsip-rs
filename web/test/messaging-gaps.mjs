// Headless messaging test: what a browser does when an item never comes, or cannot be processed. Alice and Bob talk.
// (1) A message of Alice's is lost on its way to Bob (his socket drops the push, as a mailbox past its retention would
// have lost it) and Alice then rekeys: the commit sits beyond a seq gap that cannot fill. Bob holds it, and when the
// gap has stayed open past his gap timeout he re-joins by external commit (M§6.5, M§6.8; spec-gap 69); the
// conversation carries on, the lost message gone. (2) Bob sends from an epoch Alice has moved two past before his
// message reaches her (her socket keeps it back while she rekeys twice): she cannot decrypt it. The item is rolled
// back and committed as handled (spec-gaps 44, 138), so it is acknowledged, never redelivered, even after a reload.
import { launch, person, ready, until, addContact, rowButton, checker, dump, logOf, submit, holdItems, heldCount, sleep } from './lib.mjs';

const MAILBOX_A_DID = process.env.MAILBOX_A_DID;
const check = checker();
const browser = await launch();
let alice, bob, aConv, bConv;
const mailboxBound = (p, did) => until(p.page, (d) => window.dsip.mailbox() === d, did, 20000);
const personalUp = (p) => until(p.page, () => /◇ personal /.test(document.getElementById('log').textContent), null, 20000);
const convWith = (p, did) => p.page.evaluate((d) => window.dsip.conversations().find((c) => c.kind === 'direct' && c.peer === d) || null, did);
const texts = (p, gid) => p.page.evaluate((g) => window.dsip.thread(g).map((m) => m.object.text), gid);
const count = async (p, re) => ((await logOf(p)).match(re) || []).length;
const say = async (p, gid, text) => {
  await p.page.click('nav button[data-view=messages]');
  await p.page.evaluate((g) => window.dsip.openConversation(g), gid);
  await p.page.fill('#compose-text', text);
  await p.page.click('#compose-send');
  await until(p.page, (t) => window.dsip.thread().some((m) => m.mine && m.object.text === t && m.seq != null), text, 20000);
};
const rekey = async (p, gid) => {
  const before = await count(p, /◇ committed /g);
  await p.page.evaluate((g) => window.dsip.rekey(g), gid);
  await until(p.page, (n) => (document.getElementById('log').textContent.match(/◇ committed /g) || []).length > n, before, 20000);
};
try {
  // Alice and Bob, a conversation, a message each way
  alice = await person(browser, 'Alice');
  bob = await person(browser, 'Bob');
  await mailboxBound(alice, MAILBOX_A_DID); await mailboxBound(bob, MAILBOX_A_DID);
  await personalUp(alice); await personalUp(bob);
  await addContact(alice, bob); await addContact(bob, alice);
  await rowButton(alice, bob, 'Introduce');
  await alice.page.fill('#introduce-purpose', 'gaps test');
  await submit(alice.page, 'introduce-form');
  await until(bob.page, () => window.dsip.requests().length === 1);
  await bob.page.click('#request-list button:text-is("Grant")');
  await until(alice.page, (did) => window.dsip.contactStatus(did) === 'they granted you', bob.did);
  await rowButton(alice, bob, 'Message');
  await until(alice.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did && c.members.length === 2), bob.did, 30000);
  aConv = await convWith(alice, bob.did);
  await until(bob.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did), alice.did, 30000);
  bConv = await convWith(bob, alice.did);
  await say(alice, aConv.group, 'hello');
  await until(bob.page, (g) => window.dsip.thread(g).length === 1, bConv.group, 20000);
  await say(bob, bConv.group, 'hi');
  await until(alice.page, (g) => window.dsip.thread(g).length === 2, aConv.group, 20000);
  // Alice's delivered receipt is in: nothing of hers is on its way to Bob before the message to lose
  await until(bob.page, (g) => window.dsip.thread(g).some((m) => m.mine && m.delivered), bConv.group, 20000);

  // 1. A message lost on its way to Bob, then a commit beyond the gap: held, and re-joined across when it stays open
  // the gap timeout is a setting the device starts with (each group's tracker takes it when made): 5 s, then a reload
  await bob.page.evaluate(() => window.dsip.setGapTimeout(5));
  await bob.page.reload();
  await ready(bob.page);
  await mailboxBound(bob, MAILBOX_A_DID);
  // the sync of the new binding is answered first: a sync that came after the push would deliver the message again
  // (the mailbox keeps it until Bob's acknowledgement passes it, which the held commit's will)
  await sleep(3000);
  await holdItems(bob, 'application', bConv.group, true);
  await say(alice, aConv.group, 'lost on the way');
  await until(bob.page, () => window.__tap.held.length >= 1, null, 20000);
  check('Bob: the mailbox pushed the message and it was lost before Bob saw it', (await bob.page.evaluate(() => window.__tap.drop())) === 1);
  await rekey(alice, aConv.group);
  await until(bob.page, () => /◇ hold class=handshake/.test(document.getElementById('log').textContent), null, 20000);
  check('Bob: the commit after the gap is held, not processed (M§6.5)', true);
  await until(bob.page, () => /◇ gap_timeout /.test(document.getElementById('log').textContent), null, 30000);
  check('Bob: the gap did not fill within his gap timeout (spec-gap 69)', true);
  await until(bob.page, () => /◇ joined .*kind=direct.*external=true/.test(document.getElementById('log').textContent), null, 30000);
  check('Bob: re-joined the conversation by external commit (M§6.8)', true);
  await until(alice.page, (dev) => /◇ epoch /.test(document.getElementById('log').textContent) && document.getElementById('log').textContent.includes(dev.slice(-8)),
    await bob.page.evaluate(() => window.dsip.device()), 20000);
  check('Alice: sees Bob\'s device re-join (M§7.3)', true);
  await say(alice, aConv.group, 'after the gap');
  await until(bob.page, (g) => window.dsip.thread(g).some((m) => m.object.text === 'after the gap'), bConv.group, 20000);
  await say(bob, bConv.group, 'back with you');
  await until(alice.page, (g) => window.dsip.thread(g).some((m) => m.object.text === 'back with you'), aConv.group, 20000);
  check('the conversation carries on both ways after the re-join', true);
  check('Bob: the lost message stays lost (M§6.5: the re-join starts from the current epoch)', !(await texts(bob, bConv.group)).includes('lost on the way'),
    `${JSON.stringify(await texts(bob, bConv.group))} // ${(await logOf(bob)).split('\n').filter((l) => /◇ (hold|released|gap_timeout|joined|message|duplicate|prejoin|resync)|→ sync/.test(l)).join(' // ').slice(0, 1500)}`);

  // 2. Bob's message from an epoch Alice has moved two past: unprocessable, committed as handled
  await holdItems(alice, 'application', aConv.group);
  await say(bob, bConv.group, 'from an old epoch');
  await until(alice.page, () => window.__tap.held.length >= 1, null, 20000);
  await rekey(alice, aConv.group);
  await rekey(alice, aConv.group);
  await alice.page.evaluate(() => window.__tap.release());
  await until(alice.page, () => /◇ unprocessable /.test(document.getElementById('log').textContent), null, 20000);
  check('Alice: the message could not be processed (MLS keeps one past epoch, M§6.5 rule 3)', !(await texts(alice, aConv.group)).includes('from an old epoch'));
  check('Alice: rolled back and committed as handled, not an error (spec-gaps 44, 138)', !/✗ messaging error/.test(await logOf(alice)), (await logOf(alice)).split('\n').filter((l) => /✗/.test(l)).join(' // '));
  await alice.page.reload();
  await ready(alice.page);
  await mailboxBound(alice, MAILBOX_A_DID);
  await sleep(3000);
  check('Alice: after a reload the item is not delivered again: it was acknowledged', (await count(alice, /◇ unprocessable |✗ messaging error/g)) === 0,
    (await logOf(alice)).split('\n').filter((l) => /unprocessable|✗/.test(l)).join(' // '));
  await say(bob, bConv.group, 'and from the current one');
  await until(alice.page, (g) => window.dsip.thread(g).some((m) => m.object.text === 'and from the current one'), aConv.group, 20000);
  check('Alice: the next message decrypts', true);
  check('nothing is still held on either socket', (await heldCount(alice)) === 0 && (await heldCount(bob)) === 0);
} catch (err) {
  check.fail(`exception: ${err.message}`);
  await dump(alice, bob);
}
await browser.close();
console.log(`${process.env.BROWSER || 'firefox'} messaging-gaps: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
