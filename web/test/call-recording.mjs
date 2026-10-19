// Headless test of the call glue's recording consent and sealed bodies in the browser (C§3–C§4, §10.4), against the
// CLI on the same relay:
//   1. A CLI caller declares itself recorded: Bob's incoming screen says so, and he cannot answer until he accepts
//      being recorded; then he answers.
//   2. The same caller again: Bob declines being recorded, and the caller receives reject policy.recording-declined.
//   3. Alice calls a CLI callee that answers recorded: her media is held until she accepts, then sent.
//   4. Alice seals her call bodies: her invite to Bob goes sealed, Bob's client opens it, and the call runs.
// Run by test/run.sh (FIXTURE holds the relay's certificate; DSIP_BIN the CLI).
import { spawn, execFileSync } from 'node:child_process';
import { readFileSync, rmSync } from 'node:fs';
import { launch, person, until, addContact, placeCall, checker, dump, which, URL, sleep } from './lib.mjs';

const check = checker();
const FIXTURE = process.env.FIXTURE;
const DSIP = process.env.DSIP_BIN;
const RELAY = URL.replace(/^https:/, 'wss:').replace(/\/$/, '') + '/dsip';
const CA = `${FIXTURE}/relay/cert.pem`;
const REC = 'did:web:rec.acme.example';

/** A fresh CLI identity under the fixture; returns its directory and DID. */
function cliIdentity(name) {
  const dir = `${FIXTURE}/${name}-${which}`;
  rmSync(dir, { recursive: true, force: true });
  execFileSync(DSIP, ['identity', 'init', '--dir', dir, '--name', name]);
  return { dir, did: JSON.parse(readFileSync(`${dir}/identity.json`, 'utf8')).identity };
}

/** A CLI process; `out()` is what it printed so far, `seen(re)` waits for a line. */
function cli(args) {
  const p = spawn(DSIP, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let text = '';
  p.stdout.on('data', (d) => { text += d; });
  p.stderr.on('data', (d) => { text += d; });
  const out = () => text;
  const seen = async (re, ms = 20000) => { for (let t = 0; t < ms; t += 200) { if (re.test(text)) return true; await sleep(200); } return false; };
  return { p, out, seen, stop: () => p.kill() };
}

const visible = (p, id) => p.page.evaluate((i) => !document.getElementById(i).classList.contains('hidden'), id);
const disabled = (p, id) => p.page.evaluate((i) => document.getElementById(i).disabled, id);

const browser = await launch();
let alice, bob, caller, callee;
try {
  alice = await person(browser, 'Alice');
  bob = await person(browser, 'Bob');
  const acme = cliIdentity('acme-caller');
  const callArgs = ['call', '--identity', acme.dir, '--relay', RELAY, '--ca', CA, '--to', bob.did, '--recorded-by', REC, '--media', 'none',
    '--script', 'sleep 30; quit'];

  // 1. recorded caller: no answer before acceptance (C§4)
  caller = cli(callArgs);
  await bob.page.waitForSelector('#view-incoming:not(.hidden)', { timeout: 20000 });
  await until(bob.page, () => !document.getElementById('in-recording').classList.contains('hidden'));
  const text = await bob.page.textContent('#in-recording-text');
  check('1: the incoming screen says the caller records, by whom and why (C§3)', /RECORDED/.test(text) && /compliance/.test(text), text);
  check('1: Answer and Screen wait for acceptance (C§4)', (await disabled(bob, 'btn-accept')) && (await disabled(bob, 'btn-screen')));
  check('1: nothing answered yet', !/← answer/.test(caller.out()));
  await bob.page.click('#in-recording-accept');
  await until(bob.page, () => !document.getElementById('btn-accept').disabled);
  check('1: accepting it shows accepted and enables Answer', /accepted/.test(await bob.page.textContent('#in-recording-text')) && !(await visible(bob, 'in-recording-choices')));
  await bob.page.click('#btn-accept');
  await until(bob.page, () => window.dsip.state() === 'ACTIVE');
  check('1: answered once accepted: the caller is ACTIVE', await caller.seen(/← answer\s+from/));
  await bob.page.click('#btn-hangup');
  await until(bob.page, () => window.dsip.state() === null);
  caller.stop();

  // 2. Bob declines being recorded: the caller hears policy.recording-declined
  caller = cli(callArgs);
  await bob.page.waitForSelector('#view-incoming:not(.hidden)', { timeout: 20000 });
  await until(bob.page, () => !document.getElementById('in-recording').classList.contains('hidden'));
  await bob.page.click('#in-recording-decline');
  check('2: the caller receives reject policy.recording-declined (C§4)', await caller.seen(/← reject .*reason=policy\.recording-declined/), caller.out().split('\n').filter((l) => /reject/.test(l)).join(' | '));
  await until(bob.page, () => window.dsip.state() === null);
  check('2: Bob\'s incoming screen is gone', !(await visible(bob, 'view-incoming')));
  caller.stop();

  // 3. a recorded callee: Alice's media is held until she accepts
  const acmeDesk = cliIdentity('acme-callee');
  callee = cli(['answer', '--identity', acmeDesk.dir, '--relay', RELAY, '--ca', CA, '--auto', 'accept', '--media', 'none', '--recorded-by', REC,
    '--script', 'sleep 40; quit']);
  check('3: the recorded callee is bound', await callee.seen(/capabilities/));
  await addContact(alice, { name: 'Acme', did: acmeDesk.did });
  await placeCall(alice, { name: 'Acme', did: acmeDesk.did });
  await until(alice.page, () => window.dsip.state() === 'ACTIVE');
  await until(alice.page, () => !document.getElementById('call-recording').classList.contains('hidden'));
  check('3: the call screen says the callee records', /RECORDED/.test(await alice.page.textContent('#call-recording-text')));
  check('3: Alice\'s media is held while acceptance is pending (C§4)', await alice.page.evaluate(() => window.dsip.holding() && window.dsip.recording()?.pending === true));
  await alice.page.click('#call-recording-accept');
  await until(alice.page, () => !window.dsip.holding());
  check('3: accepting sends her media again', /sending resumed/.test(await alice.page.textContent('#log')));
  await alice.page.click('#btn-hangup');
  await until(alice.page, () => window.dsip.state() === null);
  callee.stop();

  // 4. sealed bodies: Alice's invite goes sealed to Bob; his client opens it (§10.4)
  await alice.page.evaluate(() => window.dsip.setSeal(true));
  await addContact(alice, bob);
  await placeCall(alice, bob);
  await bob.page.waitForSelector('#view-incoming:not(.hidden)', { timeout: 20000 });
  check('4: Alice\'s invite went out sealed', /→ invite .*sealed/.test(await alice.page.textContent('#log')));
  await bob.page.click('#btn-accept');
  await until(alice.page, () => window.dsip.state() === 'ACTIVE');
  await until(bob.page, () => window.dsip.state() === 'ACTIVE');
  let a = 0, b = 0;
  for (let i = 0; i < 60 && !(a > 20 && b > 20); i++) { await sleep(500); a = await alice.page.evaluate(() => window.dsip.inboundPackets()); b = await bob.page.evaluate(() => window.dsip.inboundPackets()); }
  check('4: the sealed call is answered and media flows both ways', a > 20 && b > 20, `alice ${a}, bob ${b}`);
  check('4: sealing stays on (nothing was refused)', await alice.page.evaluate(() => window.dsip.seal()));
  await alice.page.click('#btn-hangup');
  await until(bob.page, () => window.dsip.state() === null);
} catch (e) {
  check.fail(`${e.message.split('\n')[0]}`);
  for (const c of [caller, callee]) if (c) console.log(`--- CLI\n${c.out().split('\n').slice(-25).join('\n')}`);
  await dump(alice, bob);
} finally {
  caller?.stop(); callee?.stop();
  await browser.close();
}
console.log(`\n${which} call-recording: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
