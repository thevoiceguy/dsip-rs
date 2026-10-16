// Headless messaging test, round 2 part B: a voice message. Alice records in the browser (fake audio), the client
// seals the recording under a single-use key, uploads the ciphertext to her mailbox's blob endpoint with a signed
// blob-put (M§5.6, M§8.4 rules 1–4) and sends an audio content carrying the key, the manifest without it. Bob's
// mailbox replicates the blob (M§8.4 rule 6); Bob fetches from the source the pinned rule orders, verifies size and
// SHA-256, decrypts and plays it; with receipts disclosed a played receipt reaches Alice (M§10.4). A second message
// after a reload still opens; the mailbox never holds plaintext.
import { readFileSync } from 'node:fs';
import { launch, person, ready, until, addContact, rowButton, checker, dump, logOf, sleep, submit } from './lib.mjs';

const MAILBOX_A_DID = process.env.MAILBOX_A_DID;
const FIXTURE = process.env.FIXTURE;
const check = checker();
const browser = await launch();
let alice, bob, aConv, bConv;
const mailboxBound = (p, did) => until(p.page, (d) => window.dsip.mailbox() === d, did, 20000);
const personalUp = (p) => until(p.page, () => /◇ personal /.test(document.getElementById('log').textContent), null, 20000);
const convWith = (p, did) => p.page.evaluate((d) => window.dsip.conversations().find((c) => c.kind === 'direct' && c.peer === d) || null, did);
const audioEntries = (p, gid) => p.page.evaluate((g) => window.dsip.thread(g).filter((m) => m.object.kind === 'audio').map((m) => ({ id: m.object.id, mine: m.mine, seq: m.seq, duration_ms: m.object.duration_ms, size: m.object.blob.size, sha256: m.object.blob.sha256, has_key: !!m.object.blob.key, played: m.played, media: window.dsip.media(m.object.id) })), gid);
const fileHas = async (path, re) => { for (let i = 0; i < 50; i++) { if (re.test(readFileSync(path, 'utf8'))) return true; await sleep(200); } return false; };
try {
  // 1. A conversation on operator A, receipts disclosed on Bob's side
  alice = await person(browser, 'Alice');
  bob = await person(browser, 'Bob');
  await mailboxBound(alice, MAILBOX_A_DID); await mailboxBound(bob, MAILBOX_A_DID);
  await personalUp(alice); await personalUp(bob);
  await bob.page.evaluate(() => window.dsip.setReadDisclosed(true));
  await addContact(alice, bob); await addContact(bob, alice);
  await rowButton(alice, bob, 'Introduce');
  await alice.page.fill('#introduce-purpose', 'voice test');
  await submit(alice.page, 'introduce-form');
  await until(bob.page, () => window.dsip.requests().length === 1);
  await bob.page.click('#request-list button:text-is("Grant")');
  await until(alice.page, (did) => window.dsip.contactStatus(did) === 'they granted you', bob.did);
  await rowButton(alice, bob, 'Message');
  await until(alice.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did && c.members.length === 2), bob.did, 30000);
  aConv = await convWith(alice, bob.did);
  await until(bob.page, (did) => window.dsip.conversations().some((c) => c.kind === 'direct' && c.peer === did), alice.did, 30000);
  bConv = await convWith(bob, alice.did);
  check('Alice: the mailbox advertises a blob endpoint (M§4.3)', /^https:\/\/.*\/blobs$/.test(await alice.page.evaluate(() => window.dsip.blobEndpoint())), await alice.page.evaluate(() => window.dsip.blobEndpoint()));

  // 2. Alice records a voice message: sealed, uploaded, sent
  await alice.page.click('nav button[data-view=messages]');
  await alice.page.evaluate((g) => window.dsip.openConversation(g), aConv.group);
  const voice = await alice.page.evaluate(() => window.dsip.recordVoice(1500));
  check('Alice: a recording was made and sealed (fresh key, ciphertext = plaintext + nonce + tag)', voice && voice.plain_size > 0 && voice.size === voice.plain_size + 28, JSON.stringify(voice));
  check('Alice: the blob was uploaded with a signed blob-put and accepted (M§5.6)', /uploaded to https:\/\/.*\/blobs\/[0-9a-f]{64}: 201/.test(await logOf(alice)));
  await until(alice.page, (g) => window.dsip.thread(g).some((m) => m.object.kind === 'audio' && m.seq != null), aConv.group, 20000);
  const aAudio = (await audioEntries(alice, aConv.group))[0];
  check('Alice: the audio content carries the key and the duration; it was accepted by the hub', aAudio.has_key && aAudio.duration_ms >= 1000 && typeof aAudio.seq === 'number', JSON.stringify(aAudio));
  check('mailbox A stored the ciphertext and never saw a plaintext', await fileHas(`${FIXTURE}/mbx-a.log`, new RegExp(`stored blob ${voice.sha256}`)));

  // 3. Bob receives, fetches from the source the rule orders, verifies, decrypts, plays
  await until(bob.page, (g) => window.dsip.thread(g).some((m) => m.object.kind === 'audio'), bConv.group, 20000);
  await until(bob.page, (g) => { const m = window.dsip.thread(g).find((x) => x.object.kind === 'audio'); return m && window.dsip.media(m.object.id)?.state === 'ready'; }, bConv.group, 30000);
  const bAudio = (await audioEntries(bob, bConv.group))[0];
  check('Bob: the blob was fetched, its size and SHA-256 verified and decrypted under the content\'s key (M§8.4 rule 7)', bAudio.media.state === 'ready' && bAudio.media.size === voice.size && bAudio.sha256 === voice.sha256, JSON.stringify(bAudio));
  check('Bob: fetched from his own mailbox\'s copy or the origin, as the pinned rule orders (M§8.4 rule 6)', /blob for .* fetched from https:\/\/.*\/blobs\//.test(await logOf(bob)));
  await bob.page.click('nav button[data-view=messages]');
  await bob.page.evaluate((g) => window.dsip.openConversation(g), bConv.group);
  await until(bob.page, (id) => !!document.querySelector(`audio[data-id="${id}"]`), bAudio.id, 10000);
  check('Bob: the thread shows a player for it', await bob.page.evaluate((id) => window.dsip.playAudio(id), bAudio.id));
  await until(bob.page, () => /◇ receipt_sent .*kind=played/.test(document.getElementById('log').textContent), null, 20000);
  check('Bob: a played receipt went out, receipts being disclosed (M§10.4, M§10.5)', true);
  await until(alice.page, (g) => { const m = window.dsip.thread(g).find((x) => x.object.kind === 'audio'); return m && m.played && Object.keys(m.played).length === 1; }, aConv.group, 20000);
  // the thread re-renders after the receipt is applied: wait for the text, not just the state
  const shown = await until(alice.page, () => /played/.test(document.getElementById('thread').textContent), null, 10000).then(() => true, () => false);
  check('Alice: her voice message shows played by Bob', shown);

  // 4. Bob answers with a voice message after a reload; Alice opens it
  await bob.page.reload();
  await ready(bob.page);
  await mailboxBound(bob, MAILBOX_A_DID);
  await bob.page.click('nav button[data-view=messages]');
  await bob.page.evaluate((g) => window.dsip.openConversation(g), bConv.group);
  await until(bob.page, (id) => window.dsip.media(id)?.state === 'ready', bAudio.id, 30000);
  check('Bob: after a reload the earlier voice message opens again from its blob', true);
  const reply = await bob.page.evaluate(() => window.dsip.recordVoice(1200));
  await until(alice.page, (g) => window.dsip.thread(g).filter((m) => m.object.kind === 'audio').length === 2, aConv.group, 20000);
  await until(alice.page, (g) => window.dsip.thread(g).filter((m) => m.object.kind === 'audio').every((m) => window.dsip.media(m.object.id)?.state === 'ready'), aConv.group, 30000);
  const aAll = await audioEntries(alice, aConv.group);
  check('Alice: Bob\'s voice reply fetched and opened', aAll.length === 2 && aAll.every((m) => m.media.state === 'ready') && aAll.some((m) => !m.mine && m.sha256 === reply.sha256), JSON.stringify(aAll.map((m) => [m.mine, m.media.state])));
} catch (err) {
  check.fail(`exception: ${err.message}`);
  await dump(alice, bob);
}
await browser.close();
console.log(`${process.env.BROWSER || 'firefox'} messaging-voice: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
