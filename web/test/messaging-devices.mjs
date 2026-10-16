// Headless messaging test, round 2 part A: history, a second device and read watermarks. Alice and Bob converse on
// one operator; Alice discloses read receipts and Bob sees her watermark, Bob keeps his private and it goes to his
// personal group only (M§10.3, M§10.5). Alice enrols a second browser from her identity file; her first device adds
// it to the personal group and the conversation and re-sends the archive keys (M§12.3, M§6.7); the second device
// reads the archive records the first one wrote as history (M§12.2), with both sides and the right seqs, then takes
// part live both ways, and a reload keeps it all (spec-gap 44).
import { launch, person, enrolled, ready, until, addContact, rowButton, checker, dump, logOf, sleep, submit } from './lib.mjs';

const MAILBOX_A_DID = process.env.MAILBOX_A_DID;
const check = checker();
const browser = await launch();
let alice, bob, alice2, aConv, bConv, a2Conv;
const mailboxBound = (p, did) => until(p.page, (d) => window.dsip.mailbox() === d, did, 20000);
const personalUp = (p) => until(p.page, () => /◇ personal /.test(document.getElementById('log').textContent), null, 20000);
const convWith = (p, did) => p.page.evaluate((d) => window.dsip.conversations().find((c) => c.kind === 'direct' && c.peer === d) || null, did);
const texts = (p, gid) => p.page.evaluate((g) => window.dsip.thread(g).map((m) => [m.mine ? 'me' : 'them', m.object.text, m.seq, !!m.from_archive]), gid);
const say = async (p, gid, text) => {
  await p.page.click('nav button[data-view=messages]');
  await p.page.evaluate((g) => window.dsip.openConversation(g), gid);
  await p.page.fill('#compose-text', text);
  await p.page.click('#compose-send');
  await until(p.page, (t) => window.dsip.thread().some((m) => m.mine && m.object.text === t && m.seq != null), text, 20000);
};
try {
  // 1. Two people on operator A, a conversation, two messages each way
  alice = await person(browser, 'Alice');
  bob = await person(browser, 'Bob');
  await mailboxBound(alice, MAILBOX_A_DID); await mailboxBound(bob, MAILBOX_A_DID);
  await personalUp(alice); await personalUp(bob);
  await addContact(alice, bob); await addContact(bob, alice);
  await rowButton(alice, bob, 'Introduce');
  await alice.page.fill('#introduce-purpose', 'history test');
  await submit(alice.page, 'introduce-form');
  await until(bob.page, () => window.dsip.requests().length === 1);
  await bob.page.click('#request-list button:text-is("Grant")');
  await until(alice.page, (did) => window.dsip.contactStatus(did) === 'they granted you', bob.did);
  await rowButton(alice, bob, 'Message');
  await until(alice.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did && c.members.length === 2), bob.did, 30000);
  aConv = await convWith(alice, bob.did);
  await until(bob.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did), alice.did, 30000);
  bConv = await convWith(bob, alice.did);
  await say(alice, aConv.group, 'one from Alice');
  await until(bob.page, () => window.dsip.thread(window.dsip.conversations().find((c) => c.kind === 'direct').group).length >= 1, null, 20000);
  await say(bob, bConv.group, 'one from Bob');
  await say(alice, aConv.group, 'two from Alice');
  await until(bob.page, () => window.dsip.thread(window.dsip.conversations().find((c) => c.kind === 'direct').group).length >= 3, null, 20000);
  await say(bob, bConv.group, 'two from Bob');
  await until(alice.page, (g) => window.dsip.thread(g).length === 4, aConv.group, 20000);
  check('both sides hold four messages in seq order', JSON.stringify((await texts(alice, aConv.group)).map((m) => m[1])) === JSON.stringify(['one from Alice', 'one from Bob', 'two from Alice', 'two from Bob']), JSON.stringify(await texts(alice, aConv.group)));
  await until(alice.page, () => /◇ archived /.test(document.getElementById('log').textContent), null, 20000);
  check('Alice archived what she showed, her own content included (M§12.2, spec-gap 51)', (await logOf(alice)).split('◇ archive ').length >= 4, String((await logOf(alice)).split('◇ archive ').length - 1));

  // 2. Read watermarks: Bob's stays private (personal group), Alice's is disclosed once she opts in
  await bob.page.click('nav button[data-view=messages]');
  await until(bob.page, () => /◇ receipt_sent .*kind=read.*via=personal group/.test(document.getElementById('log').textContent), null, 20000);
  check('Bob: his read position went to his personal group only (M§10.5)', true);
  await sleep(1500);
  check('Alice: sees no read mark from Bob', Object.keys(await alice.page.evaluate((g) => window.dsip.readMarks(g), aConv.group)).every((w) => w === alice.did));
  await alice.page.evaluate(() => window.dsip.setReadDisclosed(true));
  await alice.page.click('nav button[data-view=messages]');
  await alice.page.evaluate((g) => window.dsip.openConversation(g), aConv.group);
  await alice.page.fill('#compose-text', 'three from Alice');
  await alice.page.click('#compose-send');
  await until(bob.page, () => window.dsip.thread(window.dsip.conversations().find((c) => c.kind === 'direct').group).length === 5, null, 20000);
  await alice.page.evaluate((g) => window.dsip.openConversation(g), aConv.group);
  await until(alice.page, () => /◇ receipt_sent .*kind=read.*via=conversation/.test(document.getElementById('log').textContent), null, 20000);
  await until(bob.page, (did) => window.dsip.readMarks(window.dsip.conversations().find((c) => c.kind === 'direct').group)[did] !== undefined, alice.did, 20000);
  const bobMarks = await bob.page.evaluate((g) => window.dsip.readMarks(g), bConv.group);
  check('Bob: sees Alice read through her latest message (M§10.3)', (await texts(bob, bConv.group)).some((m) => m[1] === 'three from Alice') && !!bobMarks[alice.did], JSON.stringify(bobMarks));
  check('Bob: the thread shows which of his messages Alice has read', /read through #/.test(await bob.page.textContent('#thread-marks')), await bob.page.textContent('#thread-marks'));

  // 3. A second device of Alice, enrolled from her identity file, added by the first to the personal group and the
  //    conversation; the archive keys re-sent; it reads the history
  const file = await alice.page.evaluate(() => window.dsip.exportIdentity('correct horse battery'));
  alice2 = await enrolled(browser, 'Alice-2', file, 'correct horse battery');
  await mailboxBound(alice2, MAILBOX_A_DID);
  await until(alice2.page, () => /◇ key_packages_uploaded/.test(document.getElementById('log').textContent), null, 20000);
  check('Alice-2: bound to the mailbox as a device of the same identity and uploaded KeyPackages', (await alice2.page.evaluate(() => window.dsip.identity())) === alice.did);
  await alice.page.evaluate((did) => window.dsip.addDevice(did), await alice2.page.evaluate(() => window.dsip.device()));
  await until(alice.page, () => /re-sent \d+ archive key/.test(document.getElementById('log').textContent), null, 40000);
  check('Alice: added the device to the personal group and re-sent the archive keys (M§12.3 step 3)', /◇ committed .*personal=true/.test(await logOf(alice)));
  await until(alice.page, () => (document.getElementById('log').textContent.match(/◇ committed .*device=/g) || []).length >= 2, null, 40000);
  check('Alice: added the device to the conversation too (M§6.7)', true);
  await until(alice2.page, () => window.dsip.conversations().some((c) => c.kind === 'direct'), null, 40000);
  await until(alice2.page, () => window.dsip.thread(window.dsip.conversations().find((c) => c.kind === 'direct').group).length >= 5, null, 40000);
  a2Conv = await alice2.page.evaluate(() => window.dsip.conversations().find((c) => c.kind === 'direct'));
  const hist = await texts(alice2, a2Conv.group);
  check('Alice-2: the history, both sides, in seq order, from archive (M§12.2, M§12.3 step 5)', JSON.stringify(hist.map((m) => [m[0], m[1]])) === JSON.stringify([['me', 'one from Alice'], ['them', 'one from Bob'], ['me', 'two from Alice'], ['them', 'two from Bob'], ['me', 'three from Alice']]) && hist.every((m) => m[3]), JSON.stringify(hist));
  check('Alice-2: history came from records held until the key arrived, or opened at once; nothing sent for it', !/◇ receipt_sent/.test(await logOf(alice2)) || !/kind=delivered/.test(await logOf(alice2)));
  check('Alice-2: knows where the identity had read (archived watermark, spec-gap 68)', (await alice2.page.evaluate((g) => window.dsip.readMarks(g), a2Conv.group))[alice.did] !== undefined, JSON.stringify(await alice2.page.evaluate((g) => window.dsip.readMarks(g), a2Conv.group)));

  // 4. Live on all three: Bob's message reaches both Alices; Alice-2's reply reaches Bob and Alice-1
  await say(bob, bConv.group, 'hello both of you');
  await until(alice.page, (g) => window.dsip.thread(g).some((m) => m.object.text === 'hello both of you'), aConv.group, 20000);
  await until(alice2.page, (g) => window.dsip.thread(g).some((m) => m.object.text === 'hello both of you'), a2Conv.group, 20000);
  check('both of Alice\'s devices received Bob\'s message', true);
  await say(alice2, a2Conv.group, 'from the second device');
  await until(bob.page, (g) => window.dsip.thread(g).some((m) => m.object.text === 'from the second device'), bConv.group, 20000);
  await until(alice.page, (g) => window.dsip.thread(g).some((m) => m.object.text === 'from the second device' && m.mine), aConv.group, 20000);
  check('Alice-1 sees the sibling\'s message as her identity\'s own', true);
  // M§10.2: concurrent duplicates from two devices may still arrive; the receiver collapses them by identity
  const bobThread = await bob.page.evaluate((g) => window.dsip.thread(g), bConv.group);
  check('Bob: delivered marks on his messages are per identity, one entry for Alice however many devices (M§10.2)',
    bobThread.filter((m) => m.mine && m.delivered).every((m) => Object.keys(m.delivered).length === 1 && m.delivered[alice.did] !== undefined),
    JSON.stringify(bobThread.filter((m) => m.mine).map((m) => [m.seq, m.delivered && Object.keys(m.delivered)])));

  // 5. Alice-2 reloads: the thread, its history and the MLS state survive
  const before = await texts(alice2, a2Conv.group);
  await alice2.page.reload();
  await ready(alice2.page);
  await mailboxBound(alice2, MAILBOX_A_DID);
  await sleep(1500);
  const after = await texts(alice2, a2Conv.group);
  check('Alice-2: after a reload the thread is the same', JSON.stringify(after) === JSON.stringify(before), `${before.length} → ${after.length}`);
  await say(bob, bConv.group, 'still there, second device?');
  await until(alice2.page, (g) => window.dsip.thread(g).some((m) => m.object.text === 'still there, second device?'), a2Conv.group, 20000);
  check('Alice-2: a message after the reload decrypts', true);
} catch (err) {
  check.fail(`exception: ${err.message}`);
  for (const [p, c] of [[alice, aConv], [bob, bConv], [alice2, a2Conv]]) if (p && c) console.log(`  ${p.name} thread: ${JSON.stringify(await texts(p, c.group).catch(() => null))}`);
  await dump(alice, bob, alice2);
}
await browser.close();
console.log(`${process.env.BROWSER || 'firefox'} messaging-devices: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
