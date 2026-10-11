// Headless deployment test (stage 5): the client served by a relay with the operator's config.json beside it, TURN
// credentials minted at its /turn, and a dsip-node reached through the same origin; a second relay stands for another
// operator. Bob binds to relay B and publishes his reachability hint on the node; Alice, on relay A, looks him up
// and calls through relay B; then Bob calls her back through relay A. Env: RELAY_B, TURN_SECRET (from run.sh).
import { createHmac } from 'node:crypto';
import { launch, person, until, state, checker, dump, addContact, rowButton, sleep, URL } from './lib.mjs';

const check = checker();
const RELAY_A = URL.replace(/^https:/, 'wss:').replace(/\/$/, '') + '/dsip';
const RELAY_B = process.env.RELAY_B || 'wss://127.0.0.1:8444/dsip';
const SECRET = process.env.TURN_SECRET || '';
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';   // the relay's certificate is self-signed in the lab

const browser = await launch();
let alice, bob;
try {
  // 1. the operator's defaults reach the client from its origin
  alice = await person(browser, 'Alice');
  const served = await alice.page.evaluate(() => window.dsip.served());
  check('config.json served beside the page is in effect', Array.isArray(served.nodes) && served.nodes[0] === URL.replace(/\/$/, '') && served.publish_hint === true, JSON.stringify(served));
  const net = await alice.page.evaluate(() => window.dsip.network());
  check('Settings shows the effective network with its sources', /nodes: .*\(operator default\)/.test(net) && /relay: .*\(built-in default\)/.test(net), net.split('\n')[2]);

  // 2. TURN credentials: short-lived, minted by the relay's origin from the secret coturn holds (TURN REST API)
  const t0 = Math.floor(Date.now() / 1000);
  const turn = await (await fetch(`${URL.replace(/\/$/, '')}/turn`)).json();
  const srv = turn.iceServers?.[0] || {};
  const [exp, user] = String(srv.username || '').split(':');
  const expect = createHmac('sha1', SECRET).update(srv.username || '').digest('base64');
  check('/turn mints credentials: username <expiry>:dsip, credential HMAC-SHA1 of it under the secret', user === 'dsip' && srv.credential === expect && Number(exp) >= t0 + 500 && Number(exp) <= t0 + 700,
    `${srv.username} ttl ${turn.ttl}`);
  const iceA = await alice.page.evaluate(() => window.dsip.iceServers());
  check('the client uses them as its ICE servers when Settings and the operator set none', iceA.length === 1 && [].concat(iceA[0].urls)[0] === 'turn:127.0.0.1:3478' && /^\d+:dsip$/.test(iceA[0].username), JSON.stringify(iceA));

  // 3. Bob binds to relay B and publishes his hint on the node (through relay A's origin)
  bob = await person(browser, 'Bob');
  const relayA = await bob.page.evaluate(() => window.dsip.relay());
  await bob.page.evaluate((url) => window.dsip.setNetwork({ relay: url }), RELAY_B);
  await until(bob.page, (a) => window.dsip.relay() && window.dsip.relay() !== a, relayA);
  const published = new RegExp(`hint published → ${URL.replace(/\/$/, '')}: ${RELAY_B.replace(/[.]/g, '\\.')}( \\+ mailbox)? seq \\d+ for 3600 s: accepted`);
  await until(bob.page, (re) => new RegExp(re).test(document.getElementById('log').textContent), published.source);
  check('Bob is bound to relay B and his hint for it was accepted by the node (a newer seq than the one for relay A, published the same second)', published.test(await bob.page.textContent('#log')));
  const got = await (await fetch(`${URL.replace(/\/$/, '')}/dsip/v1/hints/${encodeURIComponent(bob.did)}`)).json();
  check('the node, reached through the relay\'s origin, holds one record for Bob', got.hints?.length === 1);
  const sel = await alice.page.evaluate((did) => window.dsip.discover(did), bob.did);
  check('Alice\'s lookup verifies it against Bob\'s DID and reads relay B from it', sel && sel.uri === RELAY_B && sel.signer.startsWith('did:key:') && sel.signer !== bob.did, JSON.stringify(sel));

  // 4. Alice calls Bob: through relay B, on a connection for the call
  await addContact(alice, bob);
  await rowButton(alice, bob, 'Call');
  await bob.page.waitForSelector('#view-incoming:not(.hidden)', { timeout: 20000 });
  check('Alice\'s call went through relay B', (await alice.page.evaluate(() => window.dsip.callRelay())) === RELAY_B, await alice.page.evaluate(() => window.dsip.route()));
  check('the call screen says so, as a hint', /via their relay .*hint-sourced, not authoritative/.test(await alice.page.evaluate(() => window.dsip.route())));
  await bob.page.click('#btn-accept');
  await until(alice.page, () => window.dsip.state() === 'ACTIVE');
  await until(bob.page, () => window.dsip.state() === 'ACTIVE');
  let a = 0, b = 0;
  for (let i = 0; i < 60 && !(a > 20 && b > 20); i++) { await sleep(500); a = await alice.page.evaluate(() => window.dsip.inboundPackets()); b = await bob.page.evaluate(() => window.dsip.inboundPackets()); }
  check('both ACTIVE on one session across two relays, media both ways', (await state(alice)) === 'ACTIVE' && (await state(bob)) === 'ACTIVE' && a > 20 && b > 20, `alice ${a}, bob ${b}`);
  const path = await alice.page.evaluate(() => window.dsip.mediaPath());
  check('the media path is reported (candidate types)', path && path.local && path.remote, JSON.stringify(path));
  check('Alice\'s log: the hint was labelled hint-sourced, and the invite went via relay B', /HINT-SOURCED, NOT AUTHORITATIVE/.test(await alice.page.textContent('#log')) && new RegExp(`→ invite .* via ${RELAY_B.replace(/[.]/g, '\\.')}`).test(await alice.page.textContent('#log')));
  await alice.page.click('#btn-hangup');
  await until(alice.page, () => window.dsip.state() === null);
  await until(bob.page, () => window.dsip.state() === null);
  await until(alice.page, () => window.dsip.callRelays().length === 0);
  check('hangup ends both; the connection to relay B is closed after the call', true);

  // 5. Bob calls Alice back: her hint names relay A, so Bob opens a connection there
  await addContact(bob, alice);
  await rowButton(bob, alice, 'Call');
  await alice.page.waitForSelector('#view-incoming:not(.hidden)', { timeout: 20000 });
  check('Bob\'s call went through relay A, from Alice\'s hint', (await bob.page.evaluate(() => window.dsip.callRelay())) === RELAY_A, await bob.page.evaluate(() => window.dsip.route()));
  await alice.page.click('#btn-accept');
  await until(alice.page, () => window.dsip.state() === 'ACTIVE');
  await until(bob.page, () => window.dsip.state() === 'ACTIVE');
  check('answered: both ACTIVE', true);
  await bob.page.click('#btn-hangup');
  await until(alice.page, () => window.dsip.state() === null);
  await until(bob.page, () => window.dsip.state() === null);

  // 6. a DID nobody published: no hint, the call goes through our own relay and ends as unknown there
  await alice.page.fill('#contact-name', 'Nobody');
  await alice.page.fill('#contact-did', 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
  await alice.page.click('#contact-add button[type=submit]');
  await alice.page.waitForSelector('#contact-list li .name:text("Nobody")');
  await alice.page.click('#contact-list li:has(.name:text("Nobody")) button:text("Call")');
  await until(alice.page, () => /hints for .*: 0 record/.test(document.getElementById('log').textContent));
  await until(alice.page, () => window.dsip.state() === null || window.dsip.state() === 'ENDED', null, 30000);
  check('no hint: the call used our own relay and ended there', (await alice.page.evaluate(() => window.dsip.callRelays())).length === 0 && /ended/.test(await alice.page.evaluate(() => window.dsip.note())), await alice.page.evaluate(() => window.dsip.note()));

  // 7. a reload keeps Bob's relay and republishes his hint
  await bob.page.reload();
  await bob.page.waitForSelector('#view-contacts:not(.hidden)');
  await until(bob.page, () => window.dsip.relay() && /hint published → .*accepted/.test(document.getElementById('log').textContent), null, 20000);
  check('after a reload Bob is bound to relay B again and his hint is re-published', (await bob.page.evaluate(() => window.dsip.network())).includes(`relay: ${RELAY_B} (yours)`));
} catch (err) {
  check.fail(`exception: ${err.stack || err}`);
  await dump(alice, bob);
} finally {
  await browser.close();
}
if (check.failures()) { console.log(`\n${check.failures()} failure(s) [${process.env.BROWSER || 'firefox'}]`); process.exit(1); }
console.log(`\nall checks passed [${process.env.BROWSER || 'firefox'}]`);
