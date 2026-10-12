// Headless messaging test: a deposit whose answer is lost goes again at the next binding (M§9.3). The page drops its
// own group-info deposits while a flag is set, so the personal group's GroupInfo (M§7.1) never reaches the hub. Alice
// then reloads: the deposit was saved as pending and is sent again once she is bound, and the personal group comes up.
// Bob's identity moves to mailbox B instead (spec-gap 122): his new mailbox learns his groups, and the GroupInfo goes
// to the hub at A through B.
import { launch, ready, until, checker, dump, sleep } from './lib.mjs';

const { MAILBOX_A_DID, MAILBOX_B, MAILBOX_B_DID } = process.env;
const URL = process.env.URL || 'https://127.0.0.1:8443/';
const check = checker();
const browser = await launch();
let alice, bob;

// While localStorage['test-drop-gi'] is set, drop outgoing group-info deposits (the payload decoded, nothing else).
const dropper = () => {
  const send = WebSocket.prototype.send;
  window.__droppedGi = 0;
  WebSocket.prototype.send = function (data) {
    try {
      if (localStorage.getItem('test-drop-gi') && typeof data === 'string') {
        const p = atob(JSON.parse(data).payload.replace(/-/g, '+').replace(/_/g, '/'));
        if (p.includes('"deposit"') && p.includes('"group-info"')) { window.__droppedGi++; return; }
      }
    } catch { /* not an envelope */ }
    return send.call(this, data);
  };
};
async function droppingPerson(name) {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  await ctx.addInitScript(dropper);
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.log(`  [${name}] page error: ${e.message}`));
  await page.goto(URL);
  await page.waitForSelector('#view-welcome:not(.hidden)');
  await page.evaluate(() => localStorage.setItem('test-drop-gi', '1'));
  await page.fill('#welcome-name', name);
  await page.click('#welcome-continue');
  await ready(page);
  return { ctx, page, name, did: await page.evaluate(() => window.dsip.identity()) };
}
const personalUp = (p, timeout = 20000) => until(p.page, () => /◇ personal /.test(document.getElementById('log').textContent), null, timeout).then(() => true, () => false);
const mailboxBound = (p, did) => until(p.page, (d) => window.dsip.mailbox() === d, did, 20000);
const undrop = (p) => p.page.evaluate(() => localStorage.removeItem('test-drop-gi'));

try {
  // 1. Both create their personal group at mailbox A; its GroupInfo deposit is dropped, so nothing confirms it
  alice = await droppingPerson('Alice');
  bob = await droppingPerson('Bob');
  await mailboxBound(alice, MAILBOX_A_DID); await mailboxBound(bob, MAILBOX_A_DID);
  await until(alice.page, () => window.__droppedGi > 0); await until(bob.page, () => window.__droppedGi > 0);
  await sleep(3000);
  check('Alice: the personal group\'s GroupInfo deposit is lost, the group is not confirmed', !(await personalUp(alice, 1)));
  check('Bob: the same', !(await personalUp(bob, 1)));

  // 2. Alice reloads: the pending GroupInfo is sent again at the binding, the hub accepts, the personal group is up
  await undrop(alice);
  await alice.page.reload();
  await ready(alice.page);
  await mailboxBound(alice, MAILBOX_A_DID);
  check('Alice: after a reload the pending deposit goes again and the personal group comes up (M§9.3)', await personalUp(alice));
  check('Alice: one personal group, not a second', (await alice.page.evaluate(() => window.dsip.conversations().filter((c) => c.kind === 'personal').length)) === 1);

  // 3. Bob moves to mailbox B: B learns his groups, and the GroupInfo reaches the hub at A through B
  await undrop(bob);
  await bob.page.evaluate(({ uri, did }) => window.dsip.setMailbox({ uri, did }), { uri: MAILBOX_B, did: MAILBOX_B_DID });
  await mailboxBound(bob, MAILBOX_B_DID);
  check('Bob: after moving to mailbox B the pending deposit goes again and the personal group comes up (spec-gap 122)', await personalUp(bob, 30000));
  const hub = await bob.page.evaluate(() => window.dsip.conversations().find((c) => c.kind === 'personal')?.hub?.did);
  check('Bob: the personal group\'s hub is still mailbox A', hub === MAILBOX_A_DID, hub);
} catch (err) {
  check.fail(`exception: ${err.message}`);
  await dump(alice, bob);
}
await browser.close();
console.log(`${process.env.BROWSER || 'firefox'} messaging-pending: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
