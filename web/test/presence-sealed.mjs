// Sealed presence (Presence Profile draft, P§12): Bob's browser seals his records, so his relay carries a state it
// cannot read. Dave was granted before Bob turned sealing on: his grant carries no keys, so he sees that Bob has
// presence but cannot read it (P§12.4). Bob adds a family audience, sealed too: the relay sees only its tag (P§12.1).
// Alice's grant, made after, names family and carries both keys sealed to her (P§12.3): her browser opens both of
// Bob's records. Revoking Alice's grant revokes it at Bob's relay and rotates both keys (P§7, P§12.5); Bob's records
// go again under the new epoch. Changing Dave's grant gives him the new key, and he reads Bob. Last,
// a second device of Bob's, enrolled from his identity file, watches its own identity, adopts the first device's
// epoch and seals there too: Dave reads both. Run by test/run.sh.
import { launch, person, enrolled, ready, until, checker, dump, addContact, rowButton, submit, which } from './lib.mjs';

const PASS = 'correct horse battery';
const check = checker();
const badge = (p, other) => p.page.evaluate((did) => window.dsip.presenceBadge(did), other.did);
const shown = (p, other) => p.page.evaluate((did) => window.dsip.presence(did), other.did);
const shows = (p, other, fn, timeout = 30000) => p.page.waitForFunction(([did, f]) => {
  const v = window.dsip.presence(did);
  return v && new Function('v', `return ${f}`)(v);
}, [other.did, fn], { timeout }).then(() => true, () => false);
const logOf = (p) => p.page.textContent('#log');
const logs = (p, re, timeout = 20000) => p.page.waitForFunction((src) => new RegExp(src).test(document.getElementById('log').textContent), re.source, { timeout })
  .then(() => true, () => false);

/** `from` introduces itself to `to`, and `to` grants it contact (§19.4), with `audience` if given: the grant admits
 *  `from` to `to`'s presence. */
async function granted(from, to, audience = '') {
  await rowButton(from, to, 'Introduce');
  await from.page.fill('#introduce-purpose', 'sealed presence');
  await submit(from.page, 'introduce-form');
  await until(to.page, () => window.dsip.requests().length >= 1, null, 30000);
  if (audience) await to.page.locator('#request-list select.grant-audience').selectOption(audience);
  await to.page.click('#request-list button:text-is("Grant")');
  await until(from.page, (did) => window.dsip.contactStatus(did) === 'they granted you', to.did, 30000);
}

/** Turn sealing on for `p`'s device: it applies when the engine starts, so the page loads again. */
async function sealOn(p) {
  await p.page.evaluate(() => window.dsip.setSealPresence(true));
  await p.page.reload();
  await ready(p.page);
}

const browser = await launch();
let alice, bob, dave, bob2;
try {
  alice = await person(browser, 'Alice');
  dave = await person(browser, 'Dave');
  bob = await person(browser, 'Bob');
  await addContact(alice, bob); await addContact(dave, bob);
  await addContact(bob, alice); await addContact(bob, dave);

  await granted(dave, bob);
  await sealOn(bob);
  check('Bob\'s device seals its presence: it holds the identity\'s key agreement secret (P§12.1)',
    (await bob.page.evaluate(() => window.dsip.sealing()))?.sealed === true, JSON.stringify(await bob.page.evaluate(() => window.dsip.sealing())));
  // a new audience joins what the device seals when the engine starts again: the page loads again (P§12.6)
  const loaded = bob.page.waitForEvent('load');
  await bob.page.evaluate(() => window.dsip.setAudience('family', 'dnd')).catch(() => {});
  await loaded; await ready(bob.page);
  const tag = (await bob.page.evaluate(() => window.dsip.sealing()))?.audiences?.family || '';
  check('the family audience is sealed, its label kept here and its tag sent (P§12.1)', /^k-[a-z2-7]{16}$/.test(tag), tag);
  await granted(alice, bob, 'family');
  check('the grant made while sealing carries the keys, sealed to Alice (P§12.3)',
    /→ grant [^\n]*with presence keys \(P§12\.3\)/.test(await logOf(bob)));
  check('Bob\'s family record is sealed under its tag\'s key, and the log names the label (P§12.1, P§12.2)',
    await logs(bob, new RegExp(`→ presence {5}sealed under ${tag}\\.0 for audience family seq`)));

  await bob.page.evaluate(() => window.dsip.setPresence('busy'));
  check('Bob\'s record goes to his relay sealed: it carries no state the relay could read (P§12.2)',
    await logs(bob, /→ presence {5}sealed under main\.0 seq/));
  await alice.page.evaluate((did) => window.dsip.watchPresence(did), bob.did);
  await dave.page.evaluate((did) => window.dsip.watchPresence(did), bob.did);
  check('Alice opens Bob\'s sealed records with the keys her grant carried: busy, and dnd for family, combined (P§4, P§12.4)',
    await shows(alice, bob, "v.source === 'record' && v.state === 'dnd' && !v.unreadable"), JSON.stringify(await shown(alice, bob)));
  check('Dave, whose grant carried no keys, sees that Bob has presence but cannot read it, and is shown no state for it (P§12.4)',
    await shows(dave, bob, "v.unreadable === 1 && v.source !== 'record'"), JSON.stringify(await shown(dave, bob)));
  check('Dave\'s badge says so', /presence not readable/.test(await badge(dave, bob) || ''), await badge(dave, bob));

  await rowButton(bob, alice, 'Revoke grant');
  check('Revoking Alice\'s grant revokes it at Bob\'s relay (P§7)', await logs(bob, /→ grant-revocation of our grant/));
  check('and rotates the keys it carried, main and family (P§12.5)',
    await logs(bob, /presence key main rotated to epoch 1/) && await logs(bob, /presence key family rotated to epoch 1/));
  check('Bob\'s record goes again, sealed under the new epoch (P§12.5)', await logs(bob, /→ presence {5}sealed under main\.1 seq/, 20000));
  check('Alice\'s watch ends and she shows nothing (P§7)',
    await alice.page.waitForFunction((did) => window.dsip.presence(did) === null, bob.did, { timeout: 20000 }).then(() => true, () => false),
    JSON.stringify(await shown(alice, bob)));

  const row = bob.page.locator('#contact-list li', { has: bob.page.locator(`code.did:text-is("${dave.did}")`) });
  await row.locator('button:text-is("Change grant")').click();
  await row.locator('.grant-edit button:text-is("Apply")').click();
  check('Changing Dave\'s grant sends one that follows it, carrying the main key at epoch 1 (§19.4, P§12.3)',
    await logs(bob, new RegExp(`→ grant +to ${dave.did.slice(0, 20)}[^\\n]*with presence keys`)));
  check('Dave now reads Bob: busy (P§12.4)',
    await shows(dave, bob, "v.source === 'record' && v.state === 'busy' && !v.unreadable"), JSON.stringify(await shown(dave, bob)));

  const file = await bob.page.evaluate((p) => window.dsip.exportIdentity(p), PASS);
  bob2 = await enrolled(browser, 'Bob-2', file, PASS);
  await sealOn(bob2);
  await bob2.page.evaluate(() => window.dsip.setPresence('away'));
  check('Bob\'s second device watches its own identity (P§6 rule 1, P§12.5)', await logs(bob2, /→ subscribe {4}our own identity/));
  check('and adopts the first device\'s epoch from its record (P§12.5)', await logs(bob2, /presence key main seen to epoch 1/, 30000));
  check('it seals under main.1 too', await logs(bob2, /→ presence {5}sealed under main\.1 seq/, 20000));
  check('Dave reads both of Bob\'s devices, combined: busy (P§4, P§12.4)',
    await logs(dave, /: busy, from 2 signed record\(s\) {3}P§4\n/, 30000), JSON.stringify(await shown(dave, bob)));
  check('no record of Bob\'s was refused', !/our presence record[^\n]* was refused/.test(await logOf(bob) + await logOf(bob2)));
} catch (e) {
  check.fail(e.message);
  await dump(...[alice, bob, dave, bob2].filter(Boolean));
} finally {
  await browser.close();
}
console.log(`\n${which} presence-sealed: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
