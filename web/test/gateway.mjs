// Headless gateway test (stage 4): the two-gateway demo with browsers as Alice, Bob, Carol and Mallory. Alice, Bob and
// Carol are did:web identities the fixture made (the browsers enrol as devices of them); their documents, the test
// number authority's policy and the gateways' documents are held in each browser as the CLI holds --did-document.
// Alice's bound number crosses to the PSTN attested (A, verified) and reaches Bob through his binding; Mallory has no
// binding and crosses downgraded; a number nobody published is refused identity.unknown; on a direct call Bob sees
// Alice's own number attested (N§4); Carol presents Carrier B's binding of Alice's number and Bob is warned that the
// number moved (N§5); a did:web name whose document is not hosted cannot bind.
import { readFileSync } from 'node:fs';
import { launch, person, enrolled, identityFile, until, state, logOf, addContact, rowButton, checker, dump } from './lib.mjs';

const F = process.env.FIXTURE;
if (!F) { console.log('FIXTURE=<dir of the gateway fixture> (web/test/run.sh makes it)'); process.exit(2); }
const read = (p) => readFileSync(`${F}/${p}`, 'utf8');
const GWA = 'did:web:gw-a.example';
const ALICE = 'did:web:alice.example', BOB = 'did:web:bob.example', CAROL = 'did:web:carol.example';
const PASS = 'correct horse battery';
const policy = read('policy.json');
const docs = ['alice', 'bob', 'carol', 'gw-a', 'gw-b'].map((n) => read(`${n}/did.json`));
const check = checker();
const browser = await launch();
let alice, bob, carol, mallory;
const hold = async (p, numbers = {}) => {
  for (const d of docs) await p.page.evaluate((t) => window.dsip.addDocument(t), d);
  await p.page.evaluate((o) => window.dsip.setNumbers(o), { policy, ...numbers });
};
const incomingAt = (p) => p.page.waitForSelector('#view-incoming:not(.hidden)', { timeout: 30000 });
const ended = async (...ps) => { for (const p of ps) await until(p.page, () => window.dsip.state() === null, null, 30000); };
try {
  alice = await enrolled(browser, 'Alice', await identityFile(`${F}/alice`, 'Alice', PASS), PASS);
  bob = await enrolled(browser, 'Bob', await identityFile(`${F}/bob`, 'Bob', PASS), PASS);
  carol = await enrolled(browser, 'Carol', await identityFile(`${F}/carol`, 'Carol', PASS), PASS);
  mallory = await person(browser, 'Mallory');
  check('did:web identities enrolled from the fixture (the same identity keys, a browser device each)', alice.did === ALICE && bob.did === BOB && carol.did === CAROL, `${alice.did} ${bob.did} ${carol.did}`);

  // a number with no nodes and no gateway: the client says what it needs
  await mallory.page.fill('#call-tn', '+15552000001');
  await mallory.page.click('#call-number button[type=submit]');
  check('calling a number needs nodes or a gateway in Settings', /needs number nodes or a gateway/.test(await mallory.page.evaluate(() => window.dsip.note())));
  await hold(alice, { gateway: GWA }); await hold(bob); await hold(carol); await hold(mallory, { gateway: GWA });

  // Alice's bound number, pasted in Settings: it verifies against her own document (N§3.4)
  await alice.page.click('nav button[data-view=settings]');
  await alice.page.fill('#set-binding', read('alice.jws').trim());
  await alice.page.click('#set-binding-save');
  await until(alice.page, () => /attested/.test(window.dsip.bindingStatus()));
  check('Alice: the binding verifies for her identity', /^\+15551234567 · number attested by Carrier Example for this identity — verifies/.test(await alice.page.evaluate(() => window.dsip.bindingStatus())), await alice.page.evaluate(() => window.dsip.bindingStatus()));
  check('Alice: her did:web document lists the number', JSON.parse(await alice.page.evaluate(() => window.dsip.didDocument())).alsoKnownAs?.includes('tel:+15551234567'));
  await alice.page.click('nav button[data-view=contacts]');

  // 1. Alice calls Bob's number: through gateway A (attested A under its delegate certificate), the trunk, gateway B
  //    (PASSporT verified, routed by Bob's published binding), to Bob
  await alice.page.fill('#call-tn', 'tel:+15552000001');
  await alice.page.click('#call-number button[type=submit]');
  await incomingAt(bob);
  check('Alice: the number is the invite\'s destination through the gateway (N§4.1)', /tel:\+15552000001 through the gateway/.test(await alice.page.evaluate(() => window.dsip.numberLine())) && /presenting \+15551234567/.test(await alice.page.evaluate(() => window.dsip.numberLine())));
  check('Bob: a PSTN caller with the verified attestation (G§5, N§4.1)', /PSTN caller \+15551234567/.test(await bob.page.textContent('#in-caller')) && (await bob.page.textContent('#in-basis')) === 'Gateway attested by gw-b.example · STIR attestation A (verified)', await bob.page.textContent('#in-basis'));
  await bob.page.click('#btn-accept');
  await until(alice.page, () => window.dsip.state() === 'ACTIVE', null, 30000);
  await until(bob.page, () => window.dsip.state() === 'ACTIVE');
  await until(alice.page, async () => (await window.dsip.inboundPackets()) > 20, null, 40000);
  await until(bob.page, async () => (await window.dsip.inboundPackets()) > 20, null, 40000);
  check('audio crosses both gateways in both directions', true);
  await alice.page.click('#btn-hangup');
  await ended(alice, bob);

  // 2. Mallory has no binding: the gateway presents its own identity; the crossing is downgraded (G§7)
  await mallory.page.fill('#call-tn', '+15552000001');
  await mallory.page.click('#call-number button[type=submit]');
  await incomingAt(bob);
  check('Bob: the crossing carried no attestation', (await bob.page.textContent('#in-basis')) === 'Gateway attested by gw-b.example · no attestation', await bob.page.textContent('#in-basis'));
  await until(mallory.page, () => /could not be asserted/.test(window.dsip.downgrade()), null, 30000);
  check('Mallory: told what the crossing lost (G§7)', /not encrypted on the PSTN trunk/.test(await mallory.page.evaluate(() => window.dsip.downgrade())), await mallory.page.evaluate(() => window.dsip.downgrade()));
  await bob.page.click('#btn-accept');
  await until(mallory.page, () => window.dsip.state() === 'ACTIVE', null, 30000);
  await mallory.page.click('#btn-hangup');
  await ended(mallory, bob);

  // 3. a number nobody published: gateway B finds no route; identity.unknown
  await alice.page.fill('#call-tn', '+15552000777');
  await alice.page.click('#call-number button[type=submit]');
  await ended(alice);
  check('Alice: a number nobody published is refused identity.unknown', /identity\.unknown/.test(await alice.page.evaluate(() => window.dsip.note())), await alice.page.evaluate(() => window.dsip.note()));

  // 4. a direct DSIP call carries Alice's own number as a claim; Bob verifies it against her document (N§4)
  await addContact(alice, bob);
  await rowButton(alice, bob, 'Call');
  await incomingAt(bob);
  check('Bob: Alice\'s own number attested for her identity (N§4)', /^☎ \+15551234567 · number attested by Carrier Example for this identity \(N§4\)$/.test(await bob.page.evaluate(() => window.dsip.inNumbers())), await bob.page.evaluate(() => window.dsip.inNumbers()));
  check('Bob: no warning (no stored contact lists the number)', (await bob.page.evaluate(() => window.dsip.inWarning())) === '');
  check('Bob: the basis stays Alice\'s own (a binding never changes it)', (await bob.page.textContent('#in-basis')) === 'Domain verified (did:web:alice.example)', await bob.page.textContent('#in-basis'));
  await bob.page.click('#btn-decline');
  await ended(alice, bob);

  // 5. N§5: Bob stores Alice with her number; Carol presents Carrier B's binding of that number: Bob is warned
  await bob.page.fill('#contact-name', 'Alice');
  await bob.page.fill('#contact-did', ALICE);
  await bob.page.fill('#contact-number', '+15551234567');
  await bob.page.click('#contact-add button[type=submit]');
  await until(bob.page, (did) => window.dsip.contacts().includes(did), ALICE);
  await carol.page.evaluate((b) => window.dsip.setBinding(b), read('carol.jws').trim());
  await addContact(carol, bob);
  await rowButton(carol, bob, 'Call');
  await incomingAt(bob);
  check('Bob: Carol\'s number attested by Carrier B', /\+15551234567 · number attested by Carrier B for this identity/.test(await bob.page.evaluate(() => window.dsip.inNumbers())), await bob.page.evaluate(() => window.dsip.inNumbers()));
  check('Bob: warned that the number moved to another identity (N§5)', /^⚠ \+15551234567 now belongs to a different identity \(number attested by Carrier B since \d{4}-\d{2}-\d{2}\)\. Your contact "Alice" is did:web:alice\.example\. \(N§5\)$/.test(await bob.page.evaluate(() => window.dsip.inWarning())), await bob.page.evaluate(() => window.dsip.inWarning()));
  await bob.page.click('#btn-decline');
  await ended(carol, bob);

  // 6. a did:web name whose document nobody serves: the relay cannot verify the hello
  await mallory.page.click('nav button[data-view=settings]');
  await mallory.page.fill('#set-did-web', 'did:web:mallory.example');
  await Promise.all([mallory.page.waitForNavigation({ waitUntil: 'load' }), mallory.page.click('#set-did-web-use', { noWaitAfter: true })]);
  await mallory.page.waitForSelector('#view-contacts:not(.hidden)');
  await until(mallory.page, () => /refused/.test(window.dsip.relayText()), null, 20000);
  check('a did:web identity is the same key under a hosted name; until the document is served, the relay refuses its hello', (await mallory.page.evaluate(() => window.dsip.identity())) === 'did:web:mallory.example', await mallory.page.evaluate(() => window.dsip.relayText()));
  check('its document is ready to host', JSON.parse(await mallory.page.evaluate(() => window.dsip.didDocument())).id === 'did:web:mallory.example');
} catch (err) {
  check.fail(`exception: ${err.stack || err}`);
  await dump(alice, bob, carol, mallory);
}
await browser.close();
if (check.failures()) { console.log(`\n${check.failures()} failure(s)`); process.exit(1); }
console.log('\nPASS: a bound number crossed two gateways attested and reached its DID, a caller without a binding crossed downgraded, an unpublished number was refused, a direct call showed the attested number, and a moved number was warned about');
