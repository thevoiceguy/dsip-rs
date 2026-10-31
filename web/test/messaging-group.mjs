// Headless messaging test, group conversations (M§7.3): Alice, Bob and Carol on one operator. Alice introduces herself
// to both and is granted; she creates a group of the three from "New group…", every member writes and every member
// reads it all. Alice removes Carol (every device of her; Bob's device checks the roster change before merging it,
// spec-gap 126): Bob sees "Alice removed Carol", and what he writes next does not reach Carol. Alice adds Carol back, and her device joins from the new welcome (spec-gap 127);
// Bob leaves, and a remaining member's device commits his removal (M§7.3 "Leaving"). Every member renders every roster
// change attributed to the committing identity, and a reload keeps them.
import { launch, person, ready, until, addContact, rowButton, checker, dump, sleep, submit } from './lib.mjs';

const MAILBOX_A_DID = process.env.MAILBOX_A_DID;
const check = checker();
const browser = await launch();
let alice, bob, carol;
const mailboxBound = (p, did) => until(p.page, (d) => window.dsip.mailbox() === d, did, 20000);
const personalUp = (p) => until(p.page, () => /◇ personal /.test(document.getElementById('log').textContent), null, 20000);
const group = (p) => p.page.evaluate(() => window.dsip.conversations().find((c) => c.kind === 'group') || null);
const groupHas = (p, n) => until(p.page, (k) => window.dsip.conversations().some((c) => c.kind === 'group' && c.members.length === k), n, 40000);
const texts = (p) => p.page.evaluate(() => { const g = window.dsip.conversations().find((c) => c.kind === 'group'); return g ? window.dsip.thread(g.group).map((m) => m.object.text) : []; });
const lines = async (p) => { await p.page.click('nav button[data-view=messages]'); await p.page.evaluate(() => window.dsip.openConversation(window.dsip.conversations().find((c) => c.kind === 'group')?.group)); return p.page.evaluate(() => window.dsip.rosterLines()); };
const say = async (p, text) => {
  await p.page.click('nav button[data-view=messages]');
  await p.page.evaluate(() => window.dsip.openConversation(window.dsip.conversations().find((c) => c.kind === 'group').group));
  await p.page.fill('#compose-text', text);
  await p.page.click('#compose-send');
  await until(p.page, (t) => window.dsip.thread().some((m) => m.mine && m.object.text === t && m.seq != null), text, 20000);
};
const sees = (p, text) => until(p.page, (t) => { const g = window.dsip.conversations().find((c) => c.kind === 'group'); return !!g && window.dsip.thread(g.group).some((m) => m.object.text === t); }, text, 20000);
const granted = async (from, to) => {
  await rowButton(from, to, 'Introduce');
  await from.page.fill('#introduce-purpose', 'a group');
  await submit(from.page, 'introduce-form');
  await until(to.page, () => window.dsip.requests().length >= 1);
  await to.page.click('#request-list button:text-is("Grant")');
  await until(from.page, (did) => window.dsip.contactStatus(did) === 'they granted you', to.did);
};
try {
  // 1. Three people on operator A; Alice holds grants from Bob and Carol (M§14.2)
  alice = await person(browser, 'Alice');
  bob = await person(browser, 'Bob');
  carol = await person(browser, 'Carol');
  for (const p of [alice, bob, carol]) { await mailboxBound(p, MAILBOX_A_DID); await personalUp(p); }
  await addContact(alice, bob); await addContact(alice, carol);
  await addContact(bob, alice); await addContact(bob, carol);
  await addContact(carol, alice); await addContact(carol, bob);
  await granted(alice, bob);
  await granted(alice, carol);

  // 2. Alice creates the group from the picker
  await alice.page.click('nav button[data-view=messages]');
  await alice.page.click('#btn-new-group');
  for (const did of [bob.did, carol.did]) await alice.page.check(`#group-picker-list input[value="${did}"]`);
  await alice.page.click('#btn-create-group');
  for (const p of [alice, bob, carol]) await groupHas(p, 3);
  check('all three hold a group conversation of three identities (M§7.3)', true);
  const ag = await group(alice);
  check('the group is hubbed at Alice\'s mailbox', ag.hub.did === MAILBOX_A_DID, ag.hub.did);
  check('Bob: the conversation is named by its other members', /group: .*Alice.*Carol|group: .*Carol.*Alice/.test(await bob.page.evaluate(() => { window.dsip.openConversation(window.dsip.conversations().find((c) => c.kind === 'group').group); return document.getElementById('thread-title').textContent; })));
  check('Bob: "Alice added you" in the thread, attributed to the committer (the welcome\'s GroupInfo signer)', (await lines(bob)).includes('Alice added you'), JSON.stringify(await lines(bob)));
  check('Alice: "you added Bob, Carol"', (await lines(alice)).some((l) => /^you added /.test(l) && /Bob/.test(l) && /Carol/.test(l)), JSON.stringify(await lines(alice)));

  // 3. Everyone writes; everyone reads it all
  await say(alice, 'hello group');
  await say(bob, 'hi from Bob');
  await say(carol, 'hi from Carol');
  for (const p of [alice, bob, carol]) for (const t of ['hello group', 'hi from Bob', 'hi from Carol']) await sees(p, t);
  check('each member holds the three messages', true);

  // 4. Alice removes Carol: every device of her, a whole identity
  await alice.page.click('nav button[data-view=messages]');
  await alice.page.evaluate((g) => window.dsip.openConversation(g), ag.group);
  // a render that changes nothing keeps the buttons: one rebuilt between press and release gets no click (Firefox)
  const kept = await alice.page.evaluate(({ g, did }) => {
    const remove = () => document.querySelector(`#group-member-list button[data-member="${did}"]`);
    const before = remove(); window.dsip.openConversation(g); return !!before && remove() === before;
  }, { g: ag.group, did: carol.did });
  check('Alice: a render that changes nothing keeps the Remove buttons in place', kept);
  await alice.page.click(`#group-member-list button[data-member="${carol.did}"]`);
  await groupHas(alice, 2);
  await groupHas(bob, 2);
  await until(carol.page, () => !window.dsip.conversations().some((c) => c.kind === 'group'), null, 30000);
  check('Carol: no longer in the group once Alice removed her', true);
  check('Bob: "Alice removed Carol" (M§7.3)', (await lines(bob)).some((l) => l === 'Alice removed Carol'), JSON.stringify(await lines(bob)));
  check('Alice: "you removed Carol"', (await lines(alice)).some((l) => l === 'you removed Carol'), JSON.stringify(await lines(alice)));
  await say(bob, 'Carol cannot read this');
  await sees(alice, 'Carol cannot read this');
  await sleep(2000);
  check('Carol: what Bob wrote after her removal does not reach her', !(await texts(carol)).includes('Carol cannot read this'), JSON.stringify(await texts(carol)));

  // 5. Alice adds Carol back from the members row
  await alice.page.selectOption('#add-member-select', carol.did);
  await alice.page.click('#btn-add-member');
  await groupHas(alice, 3); await groupHas(bob, 3); await groupHas(carol, 3);
  check('Bob: "Alice added Carol"', (await lines(bob)).some((l) => l === 'Alice added Carol'), JSON.stringify(await lines(bob)));
  check('Carol: "Alice added you" again, a join from the new welcome (spec-gap 127)', (await lines(carol)).filter((l) => l === 'Alice added you').length === 2, JSON.stringify(await lines(carol)));
  await say(carol, 'back again');
  await sees(bob, 'back again'); await sees(alice, 'back again');
  check('Carol: writes again and both read it', true);

  // 6. Bob leaves; another member's device commits his removal
  await bob.page.click('nav button[data-view=messages]');
  await bob.page.evaluate(() => window.dsip.openConversation(window.dsip.conversations().find((c) => c.kind === 'group').group));
  await bob.page.click('#btn-leave');
  await groupHas(alice, 2); await groupHas(carol, 2);
  const left = (l) => /^Bob left \(removal committed by (Alice|Carol|you)\)$/.test(l);
  check('Alice: "Bob left", and who committed it (M§7.3 "Leaving")', (await lines(alice)).some(left), JSON.stringify(await lines(alice)));
  check('Carol: "Bob left" too', (await lines(carol)).some(left), JSON.stringify(await lines(carol)));

  // 7. A reload keeps the roster changes
  const before = await lines(alice);
  await alice.page.reload();
  await ready(alice.page);
  await mailboxBound(alice, MAILBOX_A_DID);
  const after = await lines(alice);
  check('Alice: after a reload the roster changes are all still rendered', JSON.stringify(after) === JSON.stringify(before), `${JSON.stringify(before)} → ${JSON.stringify(after)}`);
  await say(carol, 'after the reload');
  await sees(alice, 'after the reload');
  check('Alice: a message after the reload decrypts', true);
} catch (err) {
  check.fail(`exception: ${err.message}`);
  for (const p of [alice, bob, carol]) if (p) console.log(`  ${p.name} thread: ${JSON.stringify(await texts(p).catch(() => null))} roster: ${JSON.stringify(await p.page.evaluate(() => window.dsip.rosterLog()).catch(() => null))}`);
  await dump(alice, bob, carol);
}
await browser.close();
console.log(`${process.env.BROWSER || 'firefox'} messaging-group: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
