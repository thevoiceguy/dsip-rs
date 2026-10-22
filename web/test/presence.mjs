// Presence (Presence Profile draft, P§3–P§5): Bob's browser signs its own presence record and keeps it at its relay;
// Alice watches him from her contact list. Before Bob picks a state she sees only his relay's claim (§9.3); once he
// does, his signed record, verified in her browser (P§3) and combined (P§4); "invisible" publishes offline (P§5).
// Then Carol binds to relay B: Alice watches her there, over a connection to Carol's relay found through her hint
// (§9.3: subscribe at the target's authority). Run by test/run.sh; env RELAY_B.
import { launch, person, until, checker, dump, addContact, sleep, which } from './lib.mjs';

const RELAY_B = process.env.RELAY_B || 'wss://127.0.0.1:8444/dsip';
const check = checker();
const badge = (p, other) => p.page.evaluate((did) => window.dsip.presenceBadge(did), other.did);
const shown = (p, other) => p.page.evaluate((did) => window.dsip.presence(did), other.did);
const shows = (p, other, fn, timeout = 30000) => p.page.waitForFunction(([did, f]) => {
  const v = window.dsip.presence(did);
  return v && new Function('v', `return ${f}`)(v);
}, [other.did, fn], { timeout }).then(() => true, () => false);

const browser = await launch();
let alice, bob, carol;
try {
  alice = await person(browser, 'Alice');
  bob = await person(browser, 'Bob');
  await addContact(alice, bob);

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
  check('Carol on relay B: Alice subscribes at Carol\'s relay and shows her record (§9.3, P§4)',
    await shows(alice, carol, "v.source === 'record' && v.state === 'dnd'", 40000), JSON.stringify(await shown(alice, carol)));
  check('Alice\'s log names the connection to relay B for presence', (await alice.page.textContent('#log')).includes('bound us for presence'));
} catch (e) {
  check.fail(e.message);
  await dump(...[alice, bob, carol].filter(Boolean));
} finally {
  await browser.close();
}
console.log(`\n${which} presence: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
