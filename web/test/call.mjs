// Headless call test: two browsers (two storage contexts, so two identities) call each other through a relay that
// serves the client. Drives the screens through the DOM, like a person would; reads state through `window.dsip`.
// Run by test/run.sh (which starts the relay); helpers and env in lib.mjs.
import { launch, person, until, state, checker, dump, which, URL } from './lib.mjs';

const check = checker();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const browser = await launch();
let alice, bob;
try {
  alice = await person(browser, 'Alice');
  bob = await person(browser, 'Bob');
  check('two identities, both bound to the relay', alice.did !== bob.did && alice.did.startsWith('did:key:'), `${alice.did.slice(0, 24)}… / ${bob.did.slice(0, 24)}…`);
  check('header shows the name and the DID', (await alice.page.textContent('#me-name')) === 'Alice' && (await alice.page.textContent('#me-did')) === alice.did);

  // Alice adds Bob and calls him
  await alice.page.fill('#contact-name', 'Bob');
  await alice.page.fill('#contact-did', bob.did);
  await alice.page.click('#contact-add button[type=submit]');
  await alice.page.waitForSelector('#contact-list li .name:text("Bob")');
  await alice.page.click('#contact-list li button:text("Call")');
  await alice.page.waitForSelector('#view-call:not(.hidden)');
  check('Alice: call screen names the callee and shows a basis line', (await alice.page.textContent('#call-peer-did')) === bob.did && (await alice.page.textContent('#call-basis')).length > 0,
    await alice.page.textContent('#call-basis'));

  // Bob sees the incoming screen with the caller's basis and the unknown-identity line
  await bob.page.waitForSelector('#view-incoming:not(.hidden)');
  check('Bob: incoming screen shows the caller DID and the §18.1 basis', (await bob.page.textContent('#in-did')) === alice.did && (await bob.page.textContent('#in-basis')).length > 0,
    await bob.page.textContent('#in-basis'));
  check('Bob: unknown identity is said so', (await bob.page.textContent('#in-contact')).includes('unknown'));
  check('Alice: ringing shown', await alice.page.waitForFunction(() => document.getElementById('call-state').textContent === 'PROCEEDING', null, { timeout: 10000 }).then(() => true, () => false));
  await bob.page.click('#btn-accept');

  await until(alice.page, () => window.dsip.state() === 'ACTIVE');
  await until(bob.page, () => window.dsip.state() === 'ACTIVE');
  check('both ACTIVE', (await state(alice)) === 'ACTIVE' && (await state(bob)) === 'ACTIVE');
  const same = (await alice.page.evaluate(() => window.dsip.session())) === (await bob.page.evaluate(() => window.dsip.session()));
  check('one session id on both sides', same);

  // media: inbound RTP on both sides (fake devices send real packets)
  let a = 0, b = 0;
  for (let i = 0; i < 60 && !(a > 20 && b > 20); i++) { await sleep(500); a = await alice.page.evaluate(() => window.dsip.inboundPackets()); b = await bob.page.evaluate(() => window.dsip.inboundPackets()); }
  check('media flows both ways (inbound RTP packets)', a > 20 && b > 20, `alice ${a}, bob ${b}`);

  // every info frame was accepted by the relay (an empty or malformed candidate would come back as a refusal)
  check('no frame of either side was refused by the relay', !/routing-refused|schema-invalid/.test(await alice.page.textContent('#log') + await bob.page.textContent('#log')));

  // hang up: both end, both are back at contacts and can call again
  await alice.page.click('#btn-hangup');
  await until(alice.page, () => window.dsip.state() === null);
  await until(bob.page, () => window.dsip.state() === null);
  check('hangup ends on both sides', true);
  await alice.page.waitForSelector('#view-contacts:not(.hidden)', { timeout: 5000 });
  await bob.page.waitForSelector('#view-contacts:not(.hidden)', { timeout: 5000 });
  const bobLog = await bob.page.textContent('#log');
  check('Bob\'s log records the bye as ended', /◆ ended/.test(bobLog));

  // second call the other way (Bob adds Alice): the client is reusable after a call
  await bob.page.fill('#contact-name', 'Alice');
  await bob.page.fill('#contact-did', alice.did);
  await bob.page.click('#contact-add button[type=submit]');
  await bob.page.click('#contact-list li button:text("Call")');
  await alice.page.waitForSelector('#view-incoming:not(.hidden)');
  check('Alice: a known contact is not flagged unknown', !(await alice.page.textContent('#in-contact')).includes('unknown'));
  await alice.page.click('#btn-decline');
  await until(bob.page, () => window.dsip.state() === null);
  check('decline ends the second call for the caller', /ended .*user\.declined/.test(await bob.page.textContent('#log')));

  // a video call: the descriptors and the SDP both carry video (B§2.1); both sides receive a video track
  await bob.page.click('#contact-list li button:text("Video")');
  await alice.page.waitForSelector('#view-incoming:not(.hidden)');
  await alice.page.click('#btn-accept');
  await until(alice.page, () => window.dsip.state() === 'ACTIVE');
  await until(bob.page, () => window.dsip.state() === 'ACTIVE');
  await until(alice.page, () => window.dsip.remoteKinds().includes('video'));
  await until(bob.page, () => window.dsip.remoteKinds().includes('video'));
  check('video call: both sides receive audio and video', JSON.stringify(await alice.page.evaluate(() => window.dsip.remoteKinds())) === '["audio","video"]');
  await bob.page.click('#btn-hangup');
  await until(alice.page, () => window.dsip.state() === null);
  await until(bob.page, () => window.dsip.state() === null);

  // export and import: a third browser imports Alice's identity file and is Alice
  const file = await alice.page.evaluate(() => window.dsip.exportIdentity('correct horse battery'));
  check('export is an encrypted identity file naming the identity', JSON.parse(file)['dsip-identity'] === 1 && JSON.parse(file).identity === alice.did && !file.includes('seed_hex'));
  const ctxC = await browser.newContext({ ignoreHTTPSErrors: true });
  const pageC = await ctxC.newPage();
  pageC.on('dialog', (d) => d.accept('correct horse battery'));
  await pageC.goto(URL);
  await pageC.waitForSelector('#view-welcome:not(.hidden)');
  await pageC.setInputFiles('#import-file', { name: 'alice.dsip-identity', mimeType: 'application/json', buffer: Buffer.from(file) });
  await pageC.waitForSelector('#view-contacts:not(.hidden)', { timeout: 15000 });
  await pageC.waitForFunction(() => window.dsip && window.dsip.relay(), null, { timeout: 15000 });
  check('import restores the identity (same DID, name)', (await pageC.evaluate(() => window.dsip.identity())) === alice.did && (await pageC.textContent('#me-name')) === 'Alice');
  const wrong = await pageC.evaluate(async (f) => { try { await window.dsip.importIdentity(f, 'wrong passphrase'); return 'accepted'; } catch (e) { return e.message; } }, file);
  check('wrong passphrase is refused', /wrong passphrase/.test(wrong), wrong);

  // persistence: reload keeps the identity and the contacts
  await alice.page.reload();
  await alice.page.waitForSelector('#view-contacts:not(.hidden)');
  check('reload keeps identity and contacts', (await alice.page.evaluate(() => window.dsip.identity())) === alice.did && (await alice.page.evaluate(() => window.dsip.contacts())).includes(bob.did));
} catch (e) {
  check.fail(e.message);
  await dump(alice, bob);
} finally {
  await browser.close();
}
console.log(`\n${which} call: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
