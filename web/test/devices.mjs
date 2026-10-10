// Headless two-device test (stage 3): one identity on two browsers, the second enrolled from the identity file with its
// own device key; a call forks to both and the one that does not answer ends without a missed call (either way
// round); the device list; a revocation signed by the identity key, handed to the relay, which ends the revoked
// device's binding and refuses its hello, after a reload too, and the next call rings only the remaining device.
import { launch, person, enrolled, ready, until, state, logOf, addContact, rowButton, checker, dump, sleep } from './lib.mjs';

const check = checker();
const browser = await launch();
const PASS = 'correct horse battery';
let alice, bob, bob2;
const incoming = (p) => p.page.isVisible('#view-incoming');
const device = (p) => p.page.evaluate(() => window.dsip.device());
try {
  alice = await person(browser, 'Alice');
  bob = await person(browser, 'Bob');

  // Bob's second browser enrols from the identity file: the same identity, a fresh device key (§7.4)
  const file = await bob.page.evaluate((p) => window.dsip.exportIdentity(p), PASS);
  bob2 = await enrolled(browser, 'Bob-2', file, PASS);
  const dev1 = await device(bob), dev2 = await device(bob2);
  check('enrolled: the same identity, a different device', bob2.did === bob.did && dev1 !== dev2, `${dev1} ${dev2}`);
  check('enrolled: the new device lists itself and the device it was enrolled from', JSON.stringify((await bob2.page.evaluate(() => window.dsip.devices())).sort()) === JSON.stringify([dev1, dev2].sort()));
  check('the file carried no device key into use (the importer made its own)', /delegated, §7\.4/.test(await logOf(bob2)));

  // Alice calls Bob: both devices ring (§12.7 forking); device 2 answers; device 1 stops, no missed call (§12.11)
  await addContact(alice, bob);
  await rowButton(alice, bob, 'Call');
  await bob.page.waitForSelector('#view-incoming:not(.hidden)', { timeout: 20000 });
  await bob2.page.waitForSelector('#view-incoming:not(.hidden)', { timeout: 20000 });
  check('forked: both of Bob\'s devices ring', true);
  await bob2.page.click('#btn-accept');
  await until(alice.page, () => window.dsip.state() === 'ACTIVE');
  await until(bob2.page, () => window.dsip.state() === 'ACTIVE');
  await until(bob.page, () => window.dsip.state() === null);
  check('device 1: the incoming screen is gone', !(await incoming(bob)));
  check('device 1: ended as answered elsewhere, never a missed call', /answered-elsewhere/.test(await logOf(bob)) && !/missed_call/.test(await logOf(bob)) && /another of your devices/.test(await bob.page.evaluate(() => window.dsip.note())), await bob.page.evaluate(() => window.dsip.note()));
  check('one session between Alice and device 2', (await alice.page.evaluate(() => window.dsip.session())) === (await bob2.page.evaluate(() => window.dsip.session())));
  await until(alice.page, async () => (await window.dsip.inboundPackets()) > 0, null, 30000);
  await until(bob2.page, async () => (await window.dsip.inboundPackets()) > 0, null, 30000);
  check('media flows between Alice and device 2', true);
  await alice.page.click('#btn-hangup');
  await until(alice.page, () => window.dsip.state() === null);
  await until(bob2.page, () => window.dsip.state() === null);

  // the other way round: device 1 answers, device 2 stops
  await rowButton(alice, bob, 'Call');
  await bob.page.waitForSelector('#view-incoming:not(.hidden)', { timeout: 20000 });
  await bob2.page.waitForSelector('#view-incoming:not(.hidden)', { timeout: 20000 });
  await bob.page.click('#btn-accept');
  await until(alice.page, () => window.dsip.state() === 'ACTIVE');
  await until(bob.page, () => window.dsip.state() === 'ACTIVE');
  await until(bob2.page, () => window.dsip.state() === null);
  check('device 2 stops when device 1 answers, no missed call', !(await incoming(bob2)) && !/missed_call/.test(await logOf(bob2)) && /another of your devices/.test(await bob2.page.evaluate(() => window.dsip.note())));
  await bob.page.click('#btn-hangup');
  await until(alice.page, () => window.dsip.state() === null);
  await until(bob.page, () => window.dsip.state() === null);

  // device 1 adds device 2 by DID and revokes it (lost): the relay ends its binding and refuses its next hello
  bob.page.on('dialog', (d) => d.accept('lost'));
  await bob.page.click('nav button[data-view=settings]');
  await bob.page.fill('#device-did', dev2);
  await bob.page.click('#device-add button[type=submit]');
  await until(bob.page, (d) => window.dsip.devices().includes(d), dev2);
  const row = bob.page.locator('#device-list li', { has: bob.page.locator(`code.did:text-is("${dev2}")`) });
  await row.locator('button:text-is("Revoke")').click();
  await until(bob.page, (d) => window.dsip.revoked().includes(d), dev2);
  check('device 1: the revocation is signed by the identity key and sent to the relay', /delegation-revocation of .* \(lost\) to the relay/.test(await logOf(bob)));
  await until(bob2.page, () => /revoked/.test(window.dsip.relayText()), null, 30000);
  check('device 2: told it was revoked, stops reconnecting', /delegation no longer verifies/.test(await bob2.page.evaluate(() => window.dsip.relayText())) && /delegation-revoked/.test(await logOf(bob2)), await bob2.page.evaluate(() => window.dsip.relayText()));

  // the next call rings device 1 only
  await bob.page.click('nav button[data-view=contacts]');
  await rowButton(alice, bob, 'Call');
  await bob.page.waitForSelector('#view-incoming:not(.hidden)', { timeout: 20000 });
  await sleep(1500);
  check('after the revocation only device 1 rings', !(await incoming(bob2)) && (await state(bob2)) === null);
  await bob.page.click('#btn-accept');
  await until(alice.page, () => window.dsip.state() === 'ACTIVE');
  await until(bob.page, () => window.dsip.state() === 'ACTIVE');
  await alice.page.click('#btn-hangup');
  await until(alice.page, () => window.dsip.state() === null);
  await until(bob.page, () => window.dsip.state() === null);

  // the relay holds the revocation: after a reload device 2's hello is refused again
  await bob2.page.reload();
  await bob2.page.waitForSelector('#view-contacts:not(.hidden)');
  await until(bob2.page, () => /revoked/.test(window.dsip.relayText()), null, 30000);
  check('device 2: refused again after a reload (the relay holds the revocation)', true);
  check('device 1: the device list shows itself and the revocation', (await bob.page.evaluate(() => window.dsip.devices())).includes(dev1) && !(await bob.page.evaluate(() => window.dsip.devices())).includes(dev2));
} catch (err) {
  check.fail(`exception: ${err.stack || err}`);
  await dump(alice, bob, bob2);
}
await browser.close();
if (check.failures()) { console.log(`\n${check.failures()} failure(s)`); process.exit(1); }
console.log('\nPASS: one identity on two devices, forked ringing with one answer and no missed call, revocation through the relay');
