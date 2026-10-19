// Headless interop test: the browser's Messenger and the native client, dsip-msg, in one conversation. Until now each
// client was only tested against itself; dsip-rs stage 3 moves both onto one library, and this is what holds them to
// the same wire meanwhile. Mailbox D, which this test starts, serves Dave (dsip-msg, did:web, an owner whose document
// names D) and enrols Alice (the browser, did:key); it admits KeyPackage fetches without a grant (M§5.7 `open`).
//   1. Alice holds Dave's document, moves to mailbox D and opens a direct conversation with him: her browser fetches
//      his KeyPackage from D (M§5.5), creates the group hubbed at D, and Dave's device joins from the welcome (M§6.7).
//   2. Text both ways (M§8.1), and the delivered receipts each client sends reach the other (M§10.2).
//   3. A voice message both ways (M§8.4): Alice's browser seals and uploads, Dave's device fetches, verifies and
//      decrypts; Dave sends an Ogg Opus file, Alice's browser fetches and decrypts it.
// Run by test/run.sh (FIXTURE, MAILBOX_BIN, NODE_URL; dsip-msg sits beside dsip-mailbox).
import { spawn } from 'node:child_process';
import { readFileSync, appendFileSync, rmSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launch, person, until, checker, dump, logOf, sleep } from './lib.mjs';

const { FIXTURE, MAILBOX_BIN, NODE_URL } = process.env;
const MSG_BIN = join(dirname(MAILBOX_BIN), 'dsip-msg');
const TONE = join(dirname(fileURLToPath(import.meta.url)), 'tone.ogg');
const MBX_D = '127.0.0.1:9446';
const DAVE = 'did:web:dave.interop.example';
const check = checker();
const browser = await launch();
let alice, mbxD, dave;

/** dsip-msg on stdin/stdout: `cmd` writes a command, `seen(re)` waits for an output line. */
function msgDevice(args) {
  const p = spawn(MSG_BIN, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  let text = '';
  p.stdout.on('data', (d) => { text += d; });
  p.stderr.on('data', (d) => { text += d; });
  const seen = async (re, ms = 30000) => { for (let t = 0; t < ms; t += 200) { const m = text.match(re); if (m) return m; await sleep(200); } return null; };
  return { p, out: () => text, cmd: (c) => p.stdin.write(`${c}\n`), seen, stop: () => { try { p.stdin.end(); } catch {} p.kill(); } };
}

try {
  // 0. Mailbox D, trusted like A and B (the fixture's CA bundle); Dave's document names it
  const dir = `${FIXTURE}/interop-${process.env.BROWSER || 'firefox'}`;
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const doc = `${dir}/dave.json`;
  mbxD = spawn(MAILBOX_BIN, ['--listen', MBX_D, '--state', `${dir}/mbx-d`, '--owner', DAVE, '--resolver-file', doc, '--serve-any', '8',
    '--admit', 'open', '--hints-node', NODE_URL, '--ca', `${FIXTURE}/mbx-ca.pem`], { stdio: 'ignore' });
  for (let i = 0; i < 80 && !existsSync(`${dir}/mbx-d/service.did`); i++) await sleep(250);
  await sleep(500);
  appendFileSync(`${FIXTURE}/mbx-ca.pem`, readFileSync(`${dir}/mbx-d/cert.pem`));
  const MAILBOX_D_DID = readFileSync(`${dir}/mbx-d/service.did`, 'utf8').trim();
  const wrote = msgDevice(['--state', `${dir}/dave`, '--identity', DAVE, '--write-doc', doc, '--mailbox-did', MAILBOX_D_DID,
    '--mailbox-uri', `wss://${MBX_D}/dsip`]);
  check('Dave: his document names mailbox D (M§4.2)', !!(await wrote.seen(/OK wrote/, 10000)), wrote.out());
  wrote.stop();

  // 1. Dave's device: bound, KeyPackages up, live
  dave = msgDevice(['--state', `${dir}/dave`, '--identity', DAVE, '--resolver-file', doc, '--ca', `${dir}/mbx-d/cert.pem`]);
  check('Dave: dsip-msg bound to mailbox D', !!(await dave.seen(/OK connected/)), dave.out());
  dave.cmd('kp 3');
  check('Dave: KeyPackages uploaded (M§5.5)', !!(await dave.seen(/OK uploaded 3 key packages/)));
  dave.cmd('live');

  // Alice: holds Dave's document (§8.1), moves to mailbox D, opens the conversation
  alice = await person(browser, 'Alice');
  await alice.page.evaluate((text) => window.dsip.addDocument(text), readFileSync(doc, 'utf8'));
  await alice.page.evaluate(({ uri, did }) => window.dsip.setMailbox({ uri, did }), { uri: `wss://${MBX_D}/dsip`, did: MAILBOX_D_DID });
  await until(alice.page, (d) => window.dsip.mailbox() === d, MAILBOX_D_DID, 20000);
  await alice.page.evaluate((did) => window.dsip.messagePeer(did), DAVE);
  await until(alice.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did && c.members.length === 2), DAVE, 30000);
  const conv = await alice.page.evaluate((did) => window.dsip.conversations().find((c) => c.kind === 'direct' && c.peer === did), DAVE);
  check('Alice: the conversation is hubbed at mailbox D, both members authenticated (M§6.2)', conv.hub.did === MAILBOX_D_DID, JSON.stringify(conv));
  check('Alice: Dave\'s mailbox was found from his document, not a hint (M§4.2)', /from their DID document/.test(await logOf(alice)));
  const joined = await dave.seen(/^JOINED (\S+) kind=direct members=(.*)$/m);
  check('Dave: dsip-msg joined from the browser\'s welcome (M§6.7)', !!joined && joined[2].includes(alice.did), joined?.[0] || dave.out().split('\n').slice(-15).join('\n'));

  // 2. text both ways, and the receipts
  await alice.page.click('nav button[data-view=messages]');
  await alice.page.evaluate((g) => window.dsip.openConversation(g), conv.group);
  await alice.page.fill('#compose-text', 'hello from the browser');
  await alice.page.click('#compose-send');
  check('Dave: dsip-msg shows the browser\'s text (M§8.1)', !!(await dave.seen(new RegExp(`^RECV ${alice.did}: hello from the browser$`, 'm'))), dave.out().split('\n').slice(-10).join('\n'));
  dave.cmd('send hello from dsip-msg');
  check('Dave: his reply was accepted by the hub', !!(await dave.seen(/^OK sent seq=/m)));
  await until(alice.page, (g) => window.dsip.thread(g).some((m) => !m.mine && m.object.text === 'hello from dsip-msg'), conv.group, 20000);
  check('Alice: the browser shows dsip-msg\'s text', true);
  check('Dave: the browser\'s delivered receipt arrived (M§10.2)', !!(await dave.seen(new RegExp(`^RECEIPT ${alice.did} delivered`, 'm'))), dave.out().split('\n').filter((l) => /RECEIPT/.test(l)).join(' | '));
  await until(alice.page, (g) => window.dsip.thread(g).some((m) => m.mine && m.object.text === 'hello from the browser' && m.delivered && Object.keys(m.delivered).length > 0), conv.group, 20000)
    .then(() => check('Alice: dsip-msg\'s delivered receipt arrived (M§10.2)', true),
      async () => check('Alice: dsip-msg\'s delivered receipt arrived (M§10.2)', false, JSON.stringify(await alice.page.evaluate((g) => window.dsip.thread(g).filter((m) => m.mine), conv.group))));

  // 3. a voice message each way (M§8.4)
  const voice = await alice.page.evaluate(() => window.dsip.recordVoice(1200));
  const got = await dave.seen(/^RECV-AUDIO (\S+) purpose=voice-message .* file=(\S+) sha256=[0-9a-f]{64} from=(\S+)$/m);
  check('Dave: dsip-msg fetched the browser\'s blob, verified size and SHA-256, and decrypted it (M§8.4 rule 7)',
    !!got && got[1] === alice.did, got?.[0] || dave.out().split('\n').filter((l) => /AUDIO|blob|BLOB/.test(l)).join(' | '));
  const played = got && existsSync(got[2]) ? readFileSync(got[2]).length : -1;
  check('Dave: what he decrypted is the size Alice recorded', played > 0 && played === voice?.plain_size, `${played} vs ${JSON.stringify(voice)}`);
  dave.cmd(`voice ${TONE}`);
  check('Dave: dsip-msg sealed, uploaded and sent an Ogg Opus voice message', !!(await dave.seen(/^OK sent audio purpose=voice-message/m)), dave.out().split('\n').slice(-6).join('\n'));
  await until(alice.page, (g) => window.dsip.thread(g).some((m) => !m.mine && m.object.kind === 'audio' && window.dsip.media(m.object.id)?.state === 'ready'), conv.group, 30000)
    .then(() => check('Alice: the browser fetched dsip-msg\'s blob, verified it and decrypted it (M§8.4 rule 7)', true),
      async () => check('Alice: the browser fetched dsip-msg\'s blob, verified it and decrypted it (M§8.4 rule 7)', false,
        JSON.stringify(await alice.page.evaluate((g) => window.dsip.thread(g).filter((m) => m.object.kind === 'audio').map((m) => ({ mine: m.mine, media: window.dsip.media(m.object.id) })), conv.group))));
} catch (e) {
  check.fail(`${e.message.split('\n')[0]}`);
  if (dave) console.log(`--- dsip-msg\n${dave.out().split('\n').slice(-30).join('\n')}`);
  await dump(alice);
} finally {
  dave?.stop(); mbxD?.kill();
  await browser.close();
}
console.log(`\n${process.env.BROWSER || 'firefox'} messaging-interop: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
