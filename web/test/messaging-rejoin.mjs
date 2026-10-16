// Headless messaging test, round 2 part C: joining by external commit (M§6.8). Alice and Bob talk; Alice's only
// device goes away. A new device of Alice, enrolled from her identity file, knows of the old one and waits to be added
// (M§12.3); nobody adds it, so it joins her personal group and the conversation by external commit from the GroupInfo
// her mailbox delivered. The hub and Bob check the joiner's identity already had a leaf there; Bob sees Alice's new
// device join; messages flow both ways. No archive key came with the join, so no history is shown (M§6.8).
import { launch, person, enrolled, ready, until, addContact, rowButton, checker, dump, logOf, submit } from './lib.mjs';

const MAILBOX_A_DID = process.env.MAILBOX_A_DID;
const check = checker();
const browser = await launch();
let alice, bob, alice2, aConv, bConv;
const mailboxBound = (p, did) => until(p.page, (d) => window.dsip.mailbox() === d, did, 20000);
const personalUp = (p) => until(p.page, () => /◇ personal /.test(document.getElementById('log').textContent), null, 20000);
const convWith = (p, did) => p.page.evaluate((d) => window.dsip.conversations().find((c) => c.kind === 'direct' && c.peer === d) || null, did);
const texts = (p, gid) => p.page.evaluate((g) => window.dsip.thread(g).map((m) => [m.mine ? 'me' : 'them', m.object.text]), gid);
const say = async (p, gid, text) => {
  await p.page.click('nav button[data-view=messages]');
  await p.page.evaluate((g) => window.dsip.openConversation(g), gid);
  await p.page.fill('#compose-text', text);
  await p.page.click('#compose-send');
  await until(p.page, (t) => window.dsip.thread().some((m) => m.mine && m.object.text === t && m.seq != null), text, 20000);
};
try {
  // 1. Alice and Bob, a conversation, a message each way
  alice = await person(browser, 'Alice');
  bob = await person(browser, 'Bob');
  await mailboxBound(alice, MAILBOX_A_DID); await mailboxBound(bob, MAILBOX_A_DID);
  await personalUp(alice); await personalUp(bob);
  await addContact(alice, bob); await addContact(bob, alice);
  await rowButton(alice, bob, 'Introduce');
  await alice.page.fill('#introduce-purpose', 'rejoin test');
  await submit(alice.page, 'introduce-form');
  await until(bob.page, () => window.dsip.requests().length === 1);
  await bob.page.click('#request-list button:text-is("Grant")');
  await until(alice.page, (did) => window.dsip.contactStatus(did) === 'they granted you', bob.did);
  await rowButton(alice, bob, 'Message');
  await until(alice.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did && c.members.length === 2), bob.did, 30000);
  aConv = await convWith(alice, bob.did);
  await until(bob.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did), alice.did, 30000);
  bConv = await convWith(bob, alice.did);
  await say(alice, aConv.group, 'before the move');
  await until(bob.page, (g) => window.dsip.thread(g).length === 1, bConv.group, 20000);
  await say(bob, bConv.group, 'got it');
  await until(alice.page, (g) => window.dsip.thread(g).length === 2, aConv.group, 20000);

  // 2. Alice's only device goes away; a new one is enrolled from her identity file and nobody adds it
  const file = await alice.page.evaluate(() => window.dsip.exportIdentity('correct horse battery'));
  const alice1Device = await alice.page.evaluate(() => window.dsip.device());
  await alice.ctx.close(); alice = null;
  alice2 = await enrolled(browser, 'Alice-2', file, 'correct horse battery');
  await mailboxBound(alice2, MAILBOX_A_DID);
  check('Alice-2: a device of the same identity, bound to her mailbox', (await alice2.page.evaluate(() => window.dsip.identity())) === bob.did ? false : true);
  await until(alice2.page, () => /waiting for another device of this identity/.test(document.getElementById('log').textContent), null, 20000);
  check('Alice-2: knows of a sibling, so it waits to be added first (M§12.3)', /joining by external commit in \d+ s/.test(await logOf(alice2)));
  await until(alice2.page, () => window.dsip.available().length >= 2, null, 20000);
  const avail = await alice2.page.evaluate(() => window.dsip.available());
  check('Alice-2: her mailbox delivered GroupInfo for the personal group and the conversation (M§6.8)', avail[0].kind === 'personal' && avail.some((g) => g.group === aConv.group), JSON.stringify(avail.map((g) => [g.kind, g.group])));

  // 3. Nobody adds it: it joins both by external commit on its own
  await until(alice2.page, () => /◇ joined .*kind=direct.*external=true/.test(document.getElementById('log').textContent), null, 90000);
  await until(alice2.page, () => !!window.dsip.personalGroup(), null, 20000);
  check('Alice-2: joined her personal group by external commit (M§6.8: the identity\'s own personal group)', (await logOf(alice2)).match(/◇ joined .*kind=personal.*external=true/) !== null);
  check('Alice-2: joined the conversation by external commit (M§6.8: her identity already had a leaf)', (await logOf(alice2)).match(/◇ joined .*kind=direct.*external=true/) !== null, (await logOf(alice2)).split('\n').filter((l) => /joined|external/.test(l)).join(' // ').slice(0, 900));
  await until(bob.page, (dev) => document.getElementById('log').textContent.includes('◇ epoch') && document.getElementById('log').textContent.includes(dev.slice(-8)), await alice2.page.evaluate(() => window.dsip.device()), 20000);
  check('Bob: verified the external join and sees Alice\'s new device join (M§6.8, M§7.3)', /◇ epoch .*added=/.test(await logOf(bob)));

  // 4. Messages flow both ways with the new device; no history came with the join
  await say(bob, bConv.group, 'welcome back');
  await until(alice2.page, (g) => window.dsip.thread(g).some((m) => m.object.text === 'welcome back'), aConv.group, 20000);
  check('Alice-2: receives Bob\'s message', true);
  await say(alice2, aConv.group, 'from the new device');
  await until(bob.page, (g) => window.dsip.thread(g).some((m) => m.object.text === 'from the new device'), bConv.group, 20000);
  check('Bob: receives the new device\'s message as Alice\'s', (await bob.page.evaluate((g) => window.dsip.thread(g).find((m) => m.object.text === 'from the new device'), bConv.group)).sender === bob.did ? false : true);
  const t2 = await texts(alice2, aConv.group);
  check('Alice-2: no history before her join: an external joiner gets no archive key (M§6.8, M§12.3)', !t2.some((m) => m[1] === 'before the move'), JSON.stringify(t2));
  check('Alice-2: the old device\'s leaf is still in the group until someone removes it', (await bob.page.evaluate((g) => window.dsip.conversations().find((c) => c.group === g).members, bConv.group)).length === 2, alice1Device.slice(-8));
} catch (err) {
  check.fail(`exception: ${err.message}`);
  await dump(alice, bob, alice2);
}
await browser.close();
console.log(`${process.env.BROWSER || 'firefox'} messaging-rejoin: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
