// Presence (Presence Profile draft, P§3–P§7): Bob's browser signs its own presence record and keeps it at its relay;
// Alice watches him from her contact list. Presence is private by default (P§6): until Bob grants her contact, his
// relay refuses her and she shows nothing. Once he grants it (the grant carries dsip.subscribe), she presents it and
// sees his relay's claim (§9.3); once he picks a state, his signed record, verified in her browser (P§3) and combined
// (P§4); "invisible" publishes offline (P§5). Carol binds to relay B: Alice watches her there, over a connection to
// Carol's relay found through her hint (§9.3). Last, Bob removes Alice: his browser revokes the grant at his relay,
// which ends her watch (P§7). Run by test/run.sh; env RELAY_B.
import { launch, person, until, checker, dump, addContact, rowButton, submit, sleep, which } from './lib.mjs';

const RELAY_B = process.env.RELAY_B || 'wss://127.0.0.1:8444/dsip';
const check = checker();
const badge = (p, other) => p.page.evaluate((did) => window.dsip.presenceBadge(did), other.did);
const shown = (p, other) => p.page.evaluate((did) => window.dsip.presence(did), other.did);
const shows = (p, other, fn, timeout = 30000) => p.page.waitForFunction(([did, f]) => {
  const v = window.dsip.presence(did);
  return v && new Function('v', `return ${f}`)(v);
}, [other.did, fn], { timeout }).then(() => true, () => false);

/** `from` introduces itself to `to`, and `to` grants it contact (§19.4): the grant admits `from` to `to`'s presence. */
async function granted(from, to) {
  await rowButton(from, to, 'Introduce');
  await from.page.fill('#introduce-purpose', 'presence');
  await submit(from.page, 'introduce-form');
  await until(to.page, () => window.dsip.requests().length >= 1, null, 30000);
  await to.page.click('#request-list button:text-is("Grant")');
  await until(from.page, (did) => window.dsip.contactStatus(did) === 'they granted you', to.did, 30000);
}

const browser = await launch();
let alice, bob, carol;
try {
  alice = await person(browser, 'Alice');
  bob = await person(browser, 'Bob');
  await addContact(alice, bob);
  await addContact(bob, alice);

  await until(alice.page, () => /presence of .*: not available from that relay/.test(document.getElementById('log').textContent), null, 30000);
  check('private by default: before Bob grants her, his relay refuses Alice and she shows nothing (P§6)',
    (await shown(alice, bob)) === null && !(await badge(alice, bob)), JSON.stringify(await shown(alice, bob)));

  await granted(alice, bob);
  await alice.page.evaluate((did) => window.dsip.watchPresence(did), bob.did);
  check('automatic: Bob sends no record, and Alice sees his relay\'s claim, marked as a claim (§9.3)',
    await shows(alice, bob, "v.source === 'assertion' && v.state === 'available'"), JSON.stringify(await shown(alice, bob)));
  check('the badge says it is the relay\'s word', (await badge(alice, bob)) === 'available (relay says)', await badge(alice, bob));

  await bob.page.evaluate(() => window.dsip.setPresence('busy'));
  check('Bob picks busy: his device signs a record, Alice verifies and shows it (P§3, P§4)',
    await shows(alice, bob, "v.source === 'record' && v.state === 'busy'"), JSON.stringify(await shown(alice, bob)));
  check('the badge shows busy', (await badge(alice, bob)) === 'busy', await badge(alice, bob));
  check('Bob\'s log shows the record going to his relay', /→ presence {5}busy seq \d+ for 300 s to our relay/.test(await bob.page.textContent('#log')));

  await bob.page.evaluate(() => window.dsip.setPresence('away'));   // within 5 s of the last one: held back, then sent (P§8)
  check('a change within the publish interval is sent once it allows (P§8)', await shows(alice, bob, "v.state === 'away'", 20000), JSON.stringify(await shown(alice, bob)));
  check('no record of Bob\'s was refused', !/our presence record was refused/.test(await bob.page.textContent('#log')));

  await sleep(5500);
  await bob.page.evaluate(() => window.dsip.setPresence('offline'));
  check('invisible publishes offline, and Alice shows Bob offline although he is bound (P§5)',
    await shows(alice, bob, "v.state === 'offline' && v.source === 'record'", 20000), JSON.stringify(await shown(alice, bob)));

  // a contact on another relay: watched at hers, found through her hint
  carol = await person(browser, 'Carol');
  await carol.page.evaluate((url) => window.dsip.setNetwork({ relay: url }), RELAY_B);
  await until(carol.page, (url) => document.getElementById('log').textContent.split('\n').some((l) => l.includes('hint published') && l.includes(`: ${url}`) && l.includes('accepted')), RELAY_B, 30000);
  await carol.page.evaluate(() => window.dsip.setPresence('dnd'));
  await addContact(alice, carol);
  await addContact(carol, alice);
  await granted(alice, carol);
  await alice.page.evaluate((did) => window.dsip.watchPresence(did), carol.did);
  check('Carol on relay B: Alice subscribes at Carol\'s relay and shows her record (§9.3, P§4)',
    await shows(alice, carol, "v.source === 'record' && v.state === 'dnd'", 40000), JSON.stringify(await shown(alice, carol)));
  check('Alice\'s log names the connection to relay B for presence', (await alice.page.textContent('#log')).includes('bound us for presence'));
  check('Alice presented Carol\'s grant (P§6)', /presence of .* at wss:.*presenting 1 grant/.test(await alice.page.textContent('#log')));

  // Bob removes Alice: the grant is revoked at his relay, which ends her watch at once (P§7)
  await rowButton(bob, alice, 'Remove');
  check('Bob\'s browser sent the revocation to his relay (§19.4)', /→ grant-revocation of our grant/.test(await bob.page.textContent('#log')));
  check('Alice: the watch ended (policy.terminated) and Bob shows nothing (P§7)',
    await alice.page.waitForFunction((did) => window.dsip.presence(did) === null, bob.did, { timeout: 20000 }).then(() => true, () => false)
    && /they stopped sharing it with us/.test(await alice.page.textContent('#log')), JSON.stringify(await shown(alice, bob)));
} catch (e) {
  check.fail(e.message);
  await dump(...[alice, bob, carol].filter(Boolean));
} finally {
  await browser.close();
}
console.log(`\n${which} presence: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
