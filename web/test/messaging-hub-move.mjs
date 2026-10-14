// Headless messaging test, moving a live hub (M§7.4): Alice on operator A opens a conversation with Bob on operator B,
// so its hub is mailbox A. Bob moves it to his own mailbox ("Host here"): the old hub orders the commit, his mailbox
// follows on `accepted` and the new hub is bootstrapped with the GroupInfo and `handover_seq`. Alice's device processes
// the moving commit and tells her mailbox the new hub (M§7.4 "Member mailboxes follow their owner's devices"), so mailbox A
// admits hub B's fan-out and forwards her deposits there: text flows both ways after the move, and both threads say who
// moved it. Then Alice moves it back, while Bob's page holds what his mailbox pushes: he writes before he has seen the
// move, the old hub answers `mailbox.unknown-group`, he syncs, finds the group moved, and his message is re-encrypted
// and re-sent to the new hub (M§7.4 "A member that missed the move"). A reload keeps the hub and the lines.
import { readFileSync } from 'node:fs';
import { launch, ready, until, addContact, rowButton, checker, dump, logOf, sleep } from './lib.mjs';

const URL = process.env.URL || 'https://127.0.0.1:8443/';
const RELAY_B = process.env.RELAY_B || 'wss://127.0.0.1:8444/dsip';
const { MAILBOX_A_DID, MAILBOX_B, MAILBOX_B_DID, FIXTURE } = process.env;
const check = checker();
const browser = await launch();
let alice, bob, aConv, bConv;
const mailboxBound = (p, did) => until(p.page, (d) => window.dsip.mailbox() === d, did, 20000);
const personalUp = (p) => until(p.page, () => /◇ personal /.test(document.getElementById('log').textContent), null, 20000);
const convWith = (p, did) => p.page.evaluate((d) => window.dsip.conversations().find((c) => c.kind === 'direct' && c.peer === d) || null, did);
const fileHas = async (path, re) => { for (let i = 0; i < 50; i++) { if (re.test(readFileSync(path, 'utf8'))) return true; await sleep(200); } return false; };
const hubOf = (p, gid) => p.page.evaluate((g) => window.dsip.conversations().find((c) => c.group === g)?.hub.did, gid);
const hubIs = (p, gid, did) => until(p.page, ({ g, d }) => window.dsip.conversations().find((c) => c.group === g)?.hub.did === d, { g: gid, d: did }, 30000);
const lines = async (p, gid) => { await p.page.click('nav button[data-view=messages]'); await p.page.evaluate((g) => window.dsip.openConversation(g), gid); return p.page.evaluate(() => window.dsip.rosterLines()); };
const say = async (p, gid, text) => {
  await p.page.click('nav button[data-view=messages]');
  await p.page.evaluate((g) => window.dsip.openConversation(g), gid);
  await p.page.fill('#compose-text', text);
  await p.page.click('#compose-send');
  await until(p.page, (t) => window.dsip.thread().some((m) => m.mine && m.object.text === t && m.seq != null), text, 30000);
};
const sees = (p, gid, text) => until(p.page, ({ g, t }) => window.dsip.thread(g).some((m) => m.object.text === t), { g: gid, t: text }, 30000);

// While localStorage['test-hold-items'] is set, inbound `items` frames are held (the payload decoded, nothing else);
// window.__releaseItems() hands them on in order. Answers to deposits (accepted, error) pass.
const holder = () => {
  window.__held = [];
  const isItems = (data) => { try { return JSON.parse(atob(JSON.parse(data).payload.replace(/-/g, '+').replace(/_/g, '/'))).type === 'items'; } catch { return false; } };
  const desc = Object.getOwnPropertyDescriptor(WebSocket.prototype, 'onmessage');
  Object.defineProperty(WebSocket.prototype, 'onmessage', {
    configurable: true,
    get() { return desc.get.call(this); },
    set(fn) {
      desc.set.call(this, async (ev) => {
        if (localStorage.getItem('test-hold-items') && typeof ev.data === 'string' && isItems(ev.data)) { window.__held.push([fn, ev]); return; }
        return fn(ev);
      });
    },
  });
  window.__releaseItems = async () => { localStorage.removeItem('test-hold-items'); const h = window.__held.splice(0); for (const [fn, ev] of h) await fn(ev); return h.length; };
};
async function holdingPerson(name) {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  await ctx.addInitScript(holder);
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.log(`  [${name}] page error: ${e.message}`));
  await page.goto(URL);
  await page.waitForSelector('#view-welcome:not(.hidden)');
  await page.fill('#welcome-name', name);
  await page.click('#welcome-continue');
  await ready(page);
  return { ctx, page, name, did: await page.evaluate(() => window.dsip.identity()) };
}

try {
  // 1. Alice on operator A, Bob on operator B; Bob grants Alice, and she opens the conversation: hubbed at mailbox A
  alice = await holdingPerson('Alice');
  await mailboxBound(alice, MAILBOX_A_DID); await personalUp(alice);
  bob = await holdingPerson('Bob');
  await bob.page.evaluate(async ({ relay, uri, did }) => { await window.dsip.setMailbox({ uri, did }); await window.dsip.setNetwork({ relay }); }, { relay: RELAY_B, uri: MAILBOX_B, did: MAILBOX_B_DID });
  await ready(bob.page);
  await mailboxBound(bob, MAILBOX_B_DID);
  await until(bob.page, (r) => new RegExp(`hint published → .*: ${r.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} \\+ mailbox .*accepted`).test(document.getElementById('log').textContent), RELAY_B);
  await addContact(alice, bob); await addContact(bob, alice);
  await rowButton(alice, bob, 'Introduce');
  await alice.page.fill('#introduce-purpose', 'hub move');
  await alice.page.click('#introduce-form button[type=submit]');
  await until(bob.page, () => window.dsip.requests().length === 1);
  await bob.page.click('#request-list button:text-is("Grant")');
  await until(alice.page, (did) => window.dsip.contactStatus(did) === 'they granted you', bob.did);
  await rowButton(alice, bob, 'Message');
  await until(alice.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did && c.members.length === 2), bob.did, 30000);
  aConv = await convWith(alice, bob.did);
  await until(bob.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did), alice.did, 30000);
  bConv = await convWith(bob, alice.did);
  check('the conversation is hubbed at Alice\'s mailbox A', aConv.hub.did === MAILBOX_A_DID && bConv.hub.did === MAILBOX_A_DID, `${aConv.hub.did} ${bConv.hub.did}`);
  await say(alice, aConv.group, 'before the move');
  await sees(bob, bConv.group, 'before the move');

  // 2. Bob moves the hub to his own mailbox
  await bob.page.click('nav button[data-view=messages]');
  await bob.page.evaluate((g) => window.dsip.openConversation(g), bConv.group);
  check('Bob: "Host here" is offered (the hub is not his mailbox)', await bob.page.isVisible('#btn-move-hub'));
  check('Alice: "Host here" is not offered (the hub is hers)', !(await alice.page.evaluate((g) => { window.dsip.openConversation(g); return !document.getElementById('btn-move-hub').classList.contains('hidden'); }, aConv.group)));
  await bob.page.click('#btn-move-hub');
  await hubIs(bob, bConv.group, MAILBOX_B_DID);
  await hubIs(alice, aConv.group, MAILBOX_B_DID);
  check('both devices now deposit to hub B (M§7.4)', true);
  check('mailbox B followed Bob\'s device, at the moving commit\'s seq', await fileHas(`${FIXTURE}/mbx-b.log`, new RegExp(`group \\S+ moved to hub ${MAILBOX_B_DID} after seq \\d+`)));
  check('mailbox A followed Alice\'s device (M§7.4 "Member mailboxes follow their owner\'s devices")', await fileHas(`${FIXTURE}/mbx-a.log`, new RegExp(`group \\S+ moved to hub ${MAILBOX_B_DID} after seq \\d+`)));
  check('Bob: "you moved the conversation\'s hub to your mailbox"', (await lines(bob, bConv.group)).includes('you moved the conversation\'s hub to your mailbox'), JSON.stringify(await lines(bob, bConv.group)));
  check('Alice: "Bob moved the conversation\'s hub to mailbox …"', (await lines(alice, aConv.group)).some((l) => /^Bob moved the conversation's hub to mailbox /.test(l)), JSON.stringify(await lines(alice, aConv.group)));
  check('Bob: "Host here" is no longer offered', !(await bob.page.evaluate((g) => { window.dsip.openConversation(g); return !document.getElementById('btn-move-hub').classList.contains('hidden'); }, bConv.group)));

  // 3. Text both ways through the new hub: hub B's fan-out is admitted at mailbox A, her deposits forwarded to it
  await say(alice, aConv.group, 'after the move, from Alice');
  await sees(bob, bConv.group, 'after the move, from Alice');
  await say(bob, bConv.group, 'after the move, from Bob');
  await sees(alice, aConv.group, 'after the move, from Bob');
  check('text flows both ways through hub B', true);

  // 4. Alice moves it back to her mailbox while Bob's page holds what his mailbox pushes: he writes before he has seen
  //    the move, so his deposit meets the old hub
  await bob.page.evaluate(() => localStorage.setItem('test-hold-items', '1'));
  await alice.page.click('nav button[data-view=messages]');
  await alice.page.evaluate((g) => window.dsip.openConversation(g), aConv.group);
  await alice.page.click('#btn-move-hub');
  await hubIs(alice, aConv.group, MAILBOX_A_DID);
  check('Alice: moved the hub back to her mailbox while Bob\'s page holds its pushes', (await hubOf(bob, bConv.group)) === MAILBOX_B_DID);
  check('mailbox A hosts the group again, numbering on after the moving commit (spec-gap 128)', await fileHas(`${FIXTURE}/mbx-a.log`, /group \S+ came back to this hub at seq \d+/));
  await bob.page.click('nav button[data-view=messages]');
  await bob.page.evaluate((g) => window.dsip.openConversation(g), bConv.group);
  await bob.page.fill('#compose-text', 'written before Bob saw the move');
  await bob.page.click('#compose-send');
  await until(bob.page, () => /◇ moved_check /.test(document.getElementById('log').textContent), null, 30000);
  check('Bob: the old hub answered mailbox.unknown-group and his device syncs (M§7.4)', true);
  const released = await bob.page.evaluate(() => window.__releaseItems());
  check('Bob: the held pushes are handed on', released >= 1, `${released}`);
  await hubIs(bob, bConv.group, MAILBOX_A_DID);
  await until(bob.page, (t) => window.dsip.thread().some((m) => m.mine && m.object.text === t && m.seq != null), 'written before Bob saw the move', 30000);
  await sees(alice, aConv.group, 'written before Bob saw the move');
  check('Bob: the message was re-encrypted and re-sent to the new hub, and Alice reads it (M§7.4)', true);
  check('Bob: "Alice moved the conversation\'s hub to mailbox …"', (await lines(bob, bConv.group)).some((l) => /^Alice moved the conversation's hub to mailbox /.test(l)), JSON.stringify(await lines(bob, bConv.group)));
  await say(alice, aConv.group, 'back at A');
  await sees(bob, bConv.group, 'back at A');

  // 5. A reload keeps the hub and the lines
  const before = await lines(alice, aConv.group);
  await alice.page.reload();
  await ready(alice.page);
  await mailboxBound(alice, MAILBOX_A_DID);
  check('Alice: after a reload the hub is still mailbox A', (await hubOf(alice, aConv.group)) === MAILBOX_A_DID);
  const after = await lines(alice, aConv.group);
  check('Alice: after a reload both hub moves are still rendered', JSON.stringify(after) === JSON.stringify(before) && after.filter((l) => / moved the conversation's hub to /.test(l)).length === 2, `${JSON.stringify(before)} → ${JSON.stringify(after)}`);
  await say(bob, bConv.group, 'after the reload');
  await sees(alice, aConv.group, 'after the reload');
  check('Alice: a message after the reload decrypts', true);
} catch (err) {
  check.fail(`exception: ${err.message}`);
  for (const p of [alice, bob]) if (p) console.log(`  ${p.name} log tail: ${(await logOf(p).catch(() => '')).split('\n').slice(-25).join('\n    ')}`);
  await dump(alice, bob);
}
await browser.close();
console.log(`${process.env.BROWSER || 'firefox'} messaging-hub-move: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
