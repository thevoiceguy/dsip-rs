// Headless messaging test (stage 6): two browsers on two operators (relay A + mailbox A as served defaults; relay B +
// mailbox B set by hand), each enrolled at its mailbox by binding (spec-gap 115), its personal group created, its
// mailbox advertised in its reachability hint (M§4.2). After first contact over the relays, Alice opens a conversation:
// Bob's mailbox found through the hint (hint-sourced), his KeyPackages fetched with the grant he issued (M§5.5, M§14.2),
// the group created at Alice's mailbox and the add committed on the hub's accepted (M§7.2, M§6.5); the welcome reaches
// Bob through hub fan-out to a mailbox found through the hint; text both ways, delivered receipts (M§10.2); Bob reloads
// and the conversation, its history and the MLS state survive (spec-gap 44), with nothing shown twice (M§8.5).
import { readFileSync } from 'node:fs';
import { launch, person, ready, until, addContact, rowButton, checker, dump, logOf, sleep } from './lib.mjs';

const RELAY_B = process.env.RELAY_B || 'wss://127.0.0.1:8444/dsip';
const MAILBOX_A = process.env.MAILBOX_A, MAILBOX_A_DID = process.env.MAILBOX_A_DID;
const MAILBOX_B = process.env.MAILBOX_B, MAILBOX_B_DID = process.env.MAILBOX_B_DID;
const FIXTURE = process.env.FIXTURE;
const check = checker();
const browser = await launch();
let alice, bob;
const mailboxBound = (p, did) => until(p.page, (d) => window.dsip.mailbox() === d, did, 20000);
const personalUp = (p) => until(p.page, () => /◇ personal /.test(document.getElementById('log').textContent), null, 20000);
const convWith = (p, did) => p.page.evaluate((d) => window.dsip.conversations().find((c) => c.kind === 'direct' && c.peer === d) || null, did);
/** A service log line may land a moment after the browser saw the effect: poll the file for it. */
const fileHas = async (path, re) => { for (let i = 0; i < 50; i++) { if (re.test(readFileSync(path, 'utf8'))) return true; await sleep(200); } return false; };
const texts = (p, gid) => p.page.evaluate((g) => window.dsip.thread(g).map((m) => [m.mine ? 'me' : 'them', m.object.text, m.seq]), gid);
try {
  // 1. Alice on operator A: the served mailbox is bound, this identity enrolled there, the personal group created
  alice = await person(browser, 'Alice');
  await mailboxBound(alice, MAILBOX_A_DID);
  check('Alice: bound to the operator default mailbox (config.json)', true);
  await personalUp(alice);
  check('Alice: personal group created at her mailbox (hub accepted its GroupInfo)', !!(await alice.page.evaluate(() => window.dsip.personalGroup())));
  check('Alice: the mailbox enrolled her identity (spec-gap 115)', await fileHas(`${FIXTURE}/mbx-a.log`, new RegExp(`enrolled ${alice.did}`)));
  await until(alice.page, () => /hint published → .*\+ mailbox .*accepted/.test(document.getElementById('log').textContent));
  check('Alice: her hint names the mailbox beside the relay (M§4.2)', true);
  check('Alice: KeyPackages uploaded (M§5.5)', /◇ key_packages_uploaded/.test(await logOf(alice)));

  // 2. Bob on operator B: relay B and mailbox B by hand; his hint names both
  bob = await person(browser, 'Bob');
  await bob.page.evaluate(async ({ relay, uri, did }) => { await window.dsip.setMailbox({ uri, did }); await window.dsip.setNetwork({ relay }); }, { relay: RELAY_B, uri: MAILBOX_B, did: MAILBOX_B_DID });
  await ready(bob.page);
  await mailboxBound(bob, MAILBOX_B_DID);
  // his personal group was made at whichever mailbox bound him first (A, or B when the move came first): not moved here
  await until(bob.page, (r) => new RegExp(`hint published → .*: ${r.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} \\+ mailbox .*accepted`).test(document.getElementById('log').textContent), RELAY_B);
  check('Bob: on relay B with mailbox B, hint published naming both', true);
  check('Bob: mailbox B enrolled him', await fileHas(`${FIXTURE}/mbx-b.log`, new RegExp(`enrolled ${bob.did}`)));

  // 3. First contact across operators (§19.4): Alice's introduction goes through relay B, which Bob's hint names, on a
  //    connection kept for his answer; his grant carries dsip.message beside dsip.invite (M§14.2)
  await addContact(alice, bob);
  await addContact(bob, alice);
  await rowButton(alice, bob, 'Introduce');
  await alice.page.fill('#introduce-purpose', 'Can we message?');
  await alice.page.click('#introduce-form button[type=submit]');
  await until(alice.page, () => /introduction to .* goes through their relay/.test(document.getElementById('log').textContent));
  check('Alice: the introduction went through relay B, named by Bob\'s hint', (await alice.page.evaluate(() => window.dsip.callRelays())).includes(RELAY_B));
  await until(bob.page, () => window.dsip.requests().length === 1);
  await bob.page.click('#request-list button:text-is("Grant")');
  await until(alice.page, (did) => window.dsip.contactStatus(did) === 'they granted you', bob.did);
  check('Alice: holds Bob\'s grant', true);
  await until(alice.page, () => /connection for the introduction closed/.test(document.getElementById('log').textContent));
  check('Alice: the connection to relay B closed once answered', !(await alice.page.evaluate(() => window.dsip.callRelays())).includes(RELAY_B));

  // 4. Alice opens the conversation: Bob's mailbox through his hint, KeyPackages fetched there, group at mailbox A
  await rowButton(alice, bob, 'Message');
  await until(alice.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did && c.members.includes(did)), bob.did, 30000);
  const aLog = await logOf(alice);
  check('Alice: Bob\'s mailbox came from his hint, said so (§8.1 rule 6)', /mailbox of .*HINT-SOURCED, NOT AUTHORITATIVE/.test(aLog));
  check('Alice: his mailbox bound her for the fetch and the grant was presented (M§5.5, M§14.2)', /their mailbox .* bound us/.test(aLog) && /presenting their grant/.test(aLog));
  check('Alice: the add was committed on the hub\'s accepted (M§6.5)', /◇ committed .*added=/.test(aLog));
  const conv = await convWith(alice, bob.did);
  check('Alice: the conversation has both identities and is hubbed at her mailbox', conv.members.length === 2 && conv.hub.did === MAILBOX_A_DID, JSON.stringify(conv));
  await until(bob.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did), alice.did, 30000);
  check('Bob: joined from the welcome his mailbox received (M§6.6, M§6.7)', /◇ joined .*kind=direct/.test(await logOf(bob)));
  check('mailbox A found Bob\'s mailbox through his hint (M§4.2, hub fan-out)', await fileHas(`${FIXTURE}/mbx-a.log`, /hint for .*DSIPMailbox endpoint/));

  // 5. Text both ways; delivered receipts
  await alice.page.evaluate((gid) => window.dsip.openConversation(gid), conv.group);
  await alice.page.fill('#compose-text', 'hello Bob');
  await alice.page.click('#compose-send');
  await until(bob.page, () => /◇ message .*/.test(document.getElementById('log').textContent), null, 20000);
  const bConv = await convWith(bob, alice.did);
  check('Bob: received the text', JSON.stringify(await texts(bob, bConv.group)).includes('hello Bob'), JSON.stringify(await texts(bob, bConv.group)));
  await until(alice.page, () => /◇ sent /.test(document.getElementById('log').textContent));
  await bob.page.click('nav button[data-view=messages]');
  await bob.page.evaluate((gid) => window.dsip.openConversation(gid), bConv.group);
  await bob.page.fill('#compose-text', 'hi Alice, it works');
  await bob.page.click('#compose-send');
  await until(alice.page, () => /◇ message .*/.test(document.getElementById('log').textContent), null, 20000);
  check('Alice: received Bob\'s reply', JSON.stringify(await texts(alice, conv.group)).includes('hi Alice, it works'));
  await until(alice.page, () => /◇ receipt .*kind=delivered/.test(document.getElementById('log').textContent), null, 20000);
  await until(bob.page, () => /◇ sent /.test(document.getElementById('log').textContent), null, 20000);
  check('Bob: the hub\'s accepted came back through his mailbox\'s forwarding (M§5.2)', true);
  check('Alice: a delivered receipt for her text came back (M§10.2)', true);
  const aThread = await alice.page.evaluate((g) => window.dsip.thread(g), conv.group);
  check('Alice: her message shows delivered', aThread.some((m) => m.mine && m.delivered && Object.keys(m.delivered).length), JSON.stringify(aThread.map((m) => [m.mine, m.seq, m.delivered])));
  check('Alice: thread has both messages with hub seqs, each once', aThread.length === 2 && aThread.every((m) => typeof m.seq === 'number'), JSON.stringify(aThread.map((m) => [m.mine, m.object.text, m.seq])));

  // 6. Bob reloads: the conversation and its history survive; a new message after the reload decrypts
  const before = await texts(bob, bConv.group);
  await bob.page.reload();
  await ready(bob.page);
  await mailboxBound(bob, MAILBOX_B_DID);
  await sleep(1500);
  const after = await texts(bob, bConv.group);
  check('Bob: after a reload the thread is the same (saved MLS and delivery state, spec-gap 44; nothing twice, M§8.5)', JSON.stringify(after) === JSON.stringify(before), `${JSON.stringify(before)} → ${JSON.stringify(after)}`);
  check('Bob: no personal group was created twice', (await logOf(bob)).split('creating the personal group').length === 1);
  await alice.page.fill('#compose-text', 'still there?');
  await alice.page.click('#compose-send');
  await until(bob.page, (n) => window.dsip.thread(window.dsip.conversations().find((c) => c.kind === 'direct').group).length === n + 1, before.length, 20000);
  check('Bob: a message after the reload decrypts with the restored MLS state', JSON.stringify(await texts(bob, bConv.group)).includes('still there?'));
  check('Bob: no duplicate or undecryptable items', !/undecryptable|◇ duplicate_content/.test(await logOf(bob)));
} catch (err) {
  check.fail(`exception: ${err.message}`);
  await dump(alice, bob);
}
await browser.close();
console.log(`${process.env.BROWSER || 'firefox'} messaging: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
