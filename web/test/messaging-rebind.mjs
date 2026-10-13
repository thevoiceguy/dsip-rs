// Headless rebind test: a device binds to its mailbox on a second connection while its first is still open (a second
// tab here; a reload whose new connection arrives before the old one has closed in practice). The new connection
// syncs live, then the first closes. The mailbox must keep pushing to the device (M§5.4: live push belongs to the
// connection that synced live). Before the fix, the old connection's end marked the device not live and handed the
// binding to a connection that had already synced, so nothing was pushed to it again (found by call-records.mjs:
// a record-keeper's reload left it deaf).
import { launch, person, ready, until, checker, dump, sleep } from './lib.mjs';

const MAILBOX_A_DID = process.env.MAILBOX_A_DID;
const check = checker();
const browser = await launch();
let alice, tab2;
try {
  alice = await person(browser, 'Alice');
  await until(alice.page, (d) => window.dsip.mailbox() === d, MAILBOX_A_DID);
  await until(alice.page, () => !!window.dsip.personalGroup(), null, 20000);
  // the same device in a second tab: a second connection beside the first, which syncs live
  const page = await alice.ctx.newPage();
  tab2 = { page, name: 'Alice (tab 2)' };
  await page.goto(process.env.URL);
  await ready(page);
  await until(page, (d) => window.dsip.mailbox() === d, MAILBOX_A_DID);
  await until(page, () => /→ sync/.test(document.getElementById('log').textContent));
  await sleep(500);
  await alice.page.close();
  alice = null;
  await sleep(1500);
  // a message to the personal group: the hub fans it back to this identity's mailbox, which pushes it to the device
  const gid = await page.evaluate(() => window.dsip.personalGroup());
  await page.evaluate(async (g) => { window.dsip.openConversation(g); await window.dsip.sendText('still here'); }, gid);
  await until(page, () => /◇ sent .*seq=2/.test(document.getElementById('log').textContent), null, 15000);
  const pushed = await until(page, () => /◇ (duplicate|self) class=application/.test(document.getElementById('log').textContent.split('◇ sent').pop()), null, 10000)
    .then(() => true, () => false);
  check('the second connection, which synced live, is pushed to after the first one closes (M§5.4)', pushed);
} catch (e) {
  check('rebind', false, e.message);
  await dump(alice, tab2);
}
await browser.close();
console.log(`${process.env.BROWSER || 'firefox'} messaging-rebind: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
