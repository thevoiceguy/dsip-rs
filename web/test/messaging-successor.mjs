// Headless messaging test, round 2 part D: successor groups (M§7.5) after a hub outage (M§9.4). Bob's mailbox is a
// third one, C, that this test starts; Bob opens the conversation, so its hub is C. Then C goes away for good. Bob
// moves to mailbox B and re-registers his groups there (spec-gap 122). Alice's next message meets an unreachable hub:
// it waits, retried with backoff, and when the hub has been gone past her threshold (12 s here, 24 h by default) her
// device creates the successor at her own mailbox: the same conversation, `successor_of` the dead group, Bob re-added
// from KeyPackages his new mailbox serves for the registered predecessor without a grant (spec-gap 61). Bob's device
// checks the successor (its creator was in the dead group, it adds nobody new) and joins; the pending message is
// re-encrypted into it and arrives; the thread keeps the dead group's history; replies flow.
import { spawn } from 'node:child_process';
import { readFileSync, appendFileSync, rmSync, existsSync } from 'node:fs';
import { launch, person, ready, until, addContact, rowButton, checker, dump, logOf, sleep } from './lib.mjs';

const { MAILBOX_A_DID, MAILBOX_B, MAILBOX_B_DID, FIXTURE, MAILBOX_BIN, NODE_URL } = process.env;
const MBX_C = '127.0.0.1:9445';
const check = checker();
const browser = await launch();
let alice, bob, mbxC, aConv, bConv;
const mailboxBound = (p, did) => until(p.page, (d) => window.dsip.mailbox() === d, did, 20000);
const personalUp = (p) => until(p.page, () => /◇ personal /.test(document.getElementById('log').textContent), null, 20000);
const convWith = (p, did) => p.page.evaluate((d) => window.dsip.conversations().find((c) => c.kind === 'direct' && c.peer === d) || null, did);
const texts = (p, gid) => p.page.evaluate((g) => window.dsip.thread(g).map((m) => [m.mine ? 'me' : 'them', m.object.text, m.seq]), gid);
const fileHas = async (path, re) => { for (let i = 0; i < 50; i++) { if (re.test(readFileSync(path, 'utf8'))) return true; await sleep(200); } return false; };
const say = async (p, gid, text, accepted = true) => {
  await p.page.click('nav button[data-view=messages]');
  await p.page.evaluate((g) => window.dsip.openConversation(g), gid);
  await p.page.fill('#compose-text', text);
  await p.page.click('#compose-send');
  if (accepted) await until(p.page, (t) => window.dsip.thread().some((m) => m.mine && m.object.text === t && m.seq != null), text, 20000);
};
try {
  // 0. Mailbox C, another operator's, trusted by A and B like each other (the fixture's CA bundle)
  rmSync(`${FIXTURE}/mbx-c`, { recursive: true, force: true });
  mbxC = spawn(MAILBOX_BIN, ['--listen', MBX_C, '--state', `${FIXTURE}/mbx-c`, '--serve-any', '8', '--hints-node', NODE_URL, '--ca', `${FIXTURE}/mbx-ca.pem`], { stdio: 'ignore' });
  for (let i = 0; i < 80 && !existsSync(`${FIXTURE}/mbx-c/service.did`); i++) await sleep(250);
  await sleep(500);
  appendFileSync(`${FIXTURE}/mbx-ca.pem`, readFileSync(`${FIXTURE}/mbx-c/cert.pem`));
  const MAILBOX_C_DID = readFileSync(`${FIXTURE}/mbx-c/service.did`, 'utf8').trim();

  // 1. Alice on mailbox A, Bob on mailbox C; Bob introduces himself, Alice grants, Bob opens the conversation (hub C)
  alice = await person(browser, 'Alice');
  bob = await person(browser, 'Bob');
  await mailboxBound(alice, MAILBOX_A_DID); await personalUp(alice);
  await mailboxBound(bob, MAILBOX_A_DID); await personalUp(bob);   // his personal group stays hubbed at A
  await bob.page.evaluate(({ uri, did }) => window.dsip.setMailbox({ uri, did }), { uri: `wss://${MBX_C}/dsip`, did: MAILBOX_C_DID });
  await mailboxBound(bob, MAILBOX_C_DID);
  // Alice's threshold is short; Bob's long, so that she creates the successor (both creating converge on the lowest
  // group id, M§7.5, which the console demos cover; here the order is fixed so the checks are)
  await alice.page.evaluate(() => window.dsip.setHubTimeout(12));
  await bob.page.evaluate(() => window.dsip.setHubTimeout(3600));
  await addContact(alice, bob); await addContact(bob, alice);
  await rowButton(bob, alice, 'Introduce');
  await bob.page.fill('#introduce-purpose', 'successor test');
  await bob.page.click('#introduce-form button[type=submit]');
  await until(alice.page, () => window.dsip.requests().length === 1);
  await alice.page.click('#request-list button:text-is("Grant")');
  await until(bob.page, (did) => window.dsip.contactStatus(did) === 'they granted you', alice.did);
  await rowButton(bob, alice, 'Message');
  await until(bob.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did && c.members.length === 2), alice.did, 30000);
  bConv = await convWith(bob, alice.did);
  await until(alice.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did), bob.did, 30000);
  aConv = await convWith(alice, bob.did);
  check('the conversation is hubbed at Bob\'s mailbox C', aConv.hub.did === MAILBOX_C_DID, aConv.hub.did);
  await say(bob, bConv.group, 'hello from Bob');
  await until(alice.page, (g) => window.dsip.thread(g).length === 1, aConv.group, 20000);
  await say(alice, aConv.group, 'hi Bob');
  await until(bob.page, (g) => window.dsip.thread(g).length === 2, bConv.group, 20000);

  // 2. Mailbox C goes away for good; Bob moves to mailbox B and re-registers his groups there
  mbxC.kill('SIGKILL'); mbxC = null;
  await bob.page.evaluate(({ uri, did }) => window.dsip.setMailbox({ uri, did }), { uri: MAILBOX_B, did: MAILBOX_B_DID });
  await mailboxBound(bob, MAILBOX_B_DID);
  await until(bob.page, () => /→ mailbox-config to mailbox/.test(document.getElementById('log').textContent.split('mailbox did:key').pop() || ''), null, 10000).catch(() => {});
  check('Bob: moved to mailbox B, enrolled there, and registered his groups (spec-gap 122)', await fileHas(`${FIXTURE}/mbx-b.log`, new RegExp(`enrolled ${bob.did}`)) && (await logOf(bob)).includes('mailbox-config'));
  await until(bob.page, () => /hint .*published|reachability/.test(document.getElementById('log').textContent), null, 10000).catch(() => {});
  await sleep(1500);

  // 3. Alice writes: the hub is unreachable, the message waits
  await say(alice, aConv.group, 'while the hub is gone', false);
  await until(alice.page, () => /◇ hub_down /.test(document.getElementById('log').textContent), null, 30000);
  check('Alice: her mailbox reports the hub unreachable; the message is kept pending (M§9.4)', (await alice.page.evaluate(() => window.dsip.thread().find((m) => m.object.text === 'while the hub is gone')))?.seq === null);

  // 4. Past the threshold Alice's device creates the successor and re-adds Bob; Bob checks it and joins
  await until(alice.page, () => /successor of .* created at our mailbox/.test(document.getElementById('log').textContent), null, 90000);
  check('Alice: fetched Bob\'s KeyPackages for the successor from his new mailbox, without a grant (M§7.5, spec-gap 61)', /key packages of .* for the successor: [1-9]/.test(await logOf(alice)));
  // the hub finds Bob's new mailbox at its next lookup (spec-gap 116: a lookup is reused at most 60 s) and retries an
  // unacknowledged welcome with backoff, so this can take a couple of minutes after a move
  await until(bob.page, () => /◇ successor /.test(document.getElementById('log').textContent), null, 180000);
  check('Bob: checked the successor (creator in the dead group, nobody added who was not) and joined it (M§7.5)', true);
  await until(bob.page, (g) => { const c = window.dsip.conversations().find((x) => x.predecessors?.includes(g)); return c && window.dsip.thread(c.group).some((m) => m.object.text === 'while the hub is gone'); }, bConv.group, 40000);
  const bNew = await bob.page.evaluate((g) => window.dsip.conversations().find((x) => x.predecessors?.includes(g)), bConv.group);
  const aNew = await alice.page.evaluate((g) => window.dsip.conversations().find((x) => x.predecessors?.includes(g)), aConv.group);
  check('both: the same successor, the same conversation, hubbed at Alice\'s mailbox A', aNew && bNew && aNew.group === bNew.group && aNew.conversation === aConv.conversation && aNew.hub.did === MAILBOX_A_DID, JSON.stringify({ a: aNew?.group, b: bNew?.group, hub: aNew?.hub?.did }));
  check('Bob: the pending message arrived, re-encrypted into the successor (M§9.4)', true);
  const bt = await texts(bob, bNew.group);
  check('Bob: one thread keeps the dead group\'s history before the successor\'s', JSON.stringify(bt.map((m) => m[1])) === JSON.stringify(['hello from Bob', 'hi Bob', 'while the hub is gone']), JSON.stringify(bt));
  check('both: the dead group is no longer listed as a conversation', (await alice.page.evaluate(() => window.dsip.conversations().filter((c) => c.kind === 'direct').length)) === 1 && (await bob.page.evaluate(() => window.dsip.conversations().filter((c) => c.kind === 'direct').length)) === 1);

  // 5. Replies flow in the successor; a reload keeps it
  await say(bob, bNew.group, 'got it in the new group');
  await until(alice.page, (g) => window.dsip.thread(g).some((m) => m.object.text === 'got it in the new group'), aNew.group, 20000);
  check('Alice: Bob\'s reply arrives in the successor', true);
  await alice.page.reload();
  await ready(alice.page);
  await mailboxBound(alice, MAILBOX_A_DID);
  const after = await alice.page.evaluate((g) => ({ list: window.dsip.conversations().filter((c) => c.kind === 'direct').map((c) => c.group), texts: window.dsip.thread(g).map((m) => m.object.text) }), aNew.group);
  check('Alice: after a reload, the successor and the whole thread are kept', JSON.stringify(after.list) === JSON.stringify([aNew.group]) && after.texts.length === 4, JSON.stringify(after));
} catch (err) {
  check.fail(`exception: ${err.message}`);
  await dump(alice, bob);
  // the mailboxes' side of the deliveries, for a failure in CI
  for (const m of ['mbx-a', 'mbx-b']) {
    const lines = readFileSync(`${FIXTURE}/${m}.log`, 'utf8').split('\n').filter((l) => /welcome|refused|unreachable|looked up|enrolled|successor/.test(l));
    console.log(`--- ${m}`); for (const l of lines.slice(-25)) console.log('   ' + l.slice(0, 260));
  }
}
mbxC?.kill('SIGKILL');
await browser.close();
console.log(`${process.env.BROWSER || 'firefox'} messaging-successor: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
