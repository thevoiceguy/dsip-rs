// Shared by the headless tests: launch a browser with fake media, make a person (a fresh storage context, so a fresh
// identity), and small waits. Env: BROWSER=firefox|chromium, URL=https://127.0.0.1:8443/.
import { readFileSync } from 'node:fs';
import { chromium, firefox } from 'playwright';
import { exportIdentity } from '../host/identity-file.js';

export const URL = process.env.URL || 'https://127.0.0.1:8443/';
export const which = process.env.BROWSER || 'firefox';
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function checker() {
  let failures = 0;
  const check = (name, ok, extra = '') => { console.log(`[${ok ? 'PASS' : 'FAIL'}] ${name} ${extra}`); if (!ok) failures++; };
  check.failures = () => failures;
  check.fail = (msg) => { console.log(`[FAIL] ${msg}`); failures++; };
  return check;
}

export async function launch() {
  if (which === 'chromium') {
    return chromium.launch({ headless: true, args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream',
      '--disable-features=WebRtcHideLocalIpsWithMdns', '--ignore-certificate-errors', '--autoplay-policy=no-user-gesture-required'] });
  }
  return firefox.launch({ headless: true, firefoxUserPrefs: {
    'media.navigator.streams.fake': true, 'media.navigator.permission.disabled': true,
    'media.peerconnection.ice.obfuscate_host_addresses': false, 'network.websocket.allowInsecureFromHTTPS': true,
    'media.autoplay.default': 0, 'media.autoplay.blocking_policy': 0,
  } });
}

/** Every page opened, so a click that hangs on one can be compared with a click on another (clickDiag). */
const pages = [];
/** Each page's own `click`, before diagnoseClicks wrapped it: the probes use it, so they never probe themselves. */
const rawClick = new WeakMap();

/** A `page.click` that times out says which parts of the browser still take input (clickDiag) in its error. */
function diagnoseClicks(page) {
  const click = page.click.bind(page);
  rawClick.set(page, click);
  page.click = async (selector, options) => {
    try { return await click(selector, options); } catch (e) {
      if (!/Timeout \d+ms exceeded/.test(e.message)) throw e;
      const page_state = await pageDiag(page);
      const input = await clickDiag(page, selector);
      e.message = `${e.message.split('\n')[0]} (${selector}); page: ${JSON.stringify(page_state)}; input: ${JSON.stringify(input)}\n${e.message}`;
      throw e;
    }
  };
}

/** Submit form `#id` the way a person does from the keyboard: Enter in its first input. Implicit submission runs the
 *  same submit handler as a click on its submit button, without the mouse.
 *  Impl: Firefox CI has hung on clicks of form submit buttons (#162, #165, #167, #172): Playwright logs "performing
 *  click action" and nothing after; the page's timer keeps running and the mouse-down never reaches the page (focus
 *  stays on the input). Firefox's automation sends every mouse event of every page through one activation chain
 *  (window focus, tab switch, compositor flush) before delivering it; key presses do not use that chain. */
export async function submit(page, id) {
  await page.locator(`#${id} input`).first().press('Enter');
}

/** A fresh browser context (fresh storage, so a fresh identity) with a page at `url`, on the welcome screen. */
export async function openPage(browser, name, url = URL) {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, permissions: which === 'chromium' ? ['camera', 'microphone'] : [] });
  await ctx.addInitScript(heartbeat);
  const page = await ctx.newPage();
  pages.push(page);
  diagnoseClicks(page);
  page.on('pageerror', (e) => console.log(`  [${name}] page error: ${e.message}`));
  page.on('console', (m) => { if (m.type() === 'error') console.log(`  [${name}] console: ${m.text()}`); });
  await page.goto(url);
  await page.waitForSelector('#view-welcome:not(.hidden)');
  return { ctx, page };
}

/** A fresh browser context at `url` (default: the client's root), through the welcome screen, bound to the relay. */
export async function person(browser, name, url = URL) {
  const { ctx, page } = await openPage(browser, name, url);
  await page.fill('#welcome-name', name);
  await page.click('#welcome-continue');
  await ready(page);
  const did = await page.evaluate(() => window.dsip.identity());
  return { ctx, page, did, name };
}

/** An identity file for an identity the CLI made (`dsip identity init`, did:web or did:key): its identity seed under
 *  `pass`, so a browser enrols as a device of it (the keys the fixture's documents and bindings name). */
export async function identityFile(dir, name, pass) {
  const meta = JSON.parse(readFileSync(`${dir}/identity.json`, 'utf8'));
  const seed = readFileSync(`${dir}/controller.key`, 'utf8').trim();
  return exportIdentity({ controller_seed_hex: seed, identity: meta.identity, display_name: name || meta.display_name }, pass);
}

/** A fresh browser context enrolled as a device of the identity in `file` (the welcome screen's import, passphrase
 *  answered through the dialog), bound to the relay. The dialog handler stays: later prompts get `pass` too. */
export async function enrolled(browser, name, file, pass, url = URL) {
  const { ctx, page } = await openPage(browser, name, url);
  page.on('dialog', (d) => d.accept(pass));
  await page.setInputFiles('#import-file', { name: 'identity.dsip-identity', mimeType: 'application/json', buffer: Buffer.from(file) });
  await ready(page);
  const did = await page.evaluate(() => window.dsip.identity());
  return { ctx, page, did, name };
}

/** A page timer every 250 ms: the longest gap between ticks says how long the main thread was ever held (pageDiag). */
function heartbeat() {
  window.__beat = Date.now(); window.__maxGap = 0;
  setInterval(() => { const n = Date.now(); window.__maxGap = Math.max(window.__maxGap, n - window.__beat); window.__beat = n; }, 250);
}

/** What the page is doing, for a failure report: whether it answers at all within 5 s (a held main thread does not),
 *  how long since its timer last ran, the longest gap so far, and the log's last lines. */
export async function pageDiag(page) {
  const probe = page.evaluate(() => ({
    readyState: document.readyState, since_beat_ms: window.__beat ? Date.now() - window.__beat : null, max_gap_ms: window.__maxGap ?? null,
    focused: document.activeElement?.id || document.activeElement?.tagName || null, view: document.querySelector('main > section:not(.hidden)')?.id || null,
    log_tail: (document.getElementById('log')?.textContent || '').trim().split('\n').slice(-4).map((l) => l.trim().slice(0, 160)),
  })).catch((e) => ({ evaluate_error: e.message.split('\n')[0] }));
  return Promise.race([probe, sleep(5000).then(() => ({ unresponsive: 'the page did not answer an evaluate within 5 s: its main thread is held' }))]);
}

/** After a click on `page` timed out: which parts of the browser still take input. Firefox's automation (Juggler) runs
 *  every mouse event of every page through one activation chain; typing does not use it. So: a key press on the same
 *  page, a click on another page, bringing the page to the front, and the same click again, each bounded by 5 s. */
export async function clickDiag(page, selector, keyTarget) {
  const out = {};
  const timed = async (name, f) => {
    const t = Date.now();
    out[name] = await Promise.race([f().then(() => `${Date.now() - t} ms`, (e) => `failed: ${e.message.split('\n')[0]}`),
      sleep(5500).then(() => 'no answer in 5.5 s')]);
  };
  if (keyTarget) await timed('key_same_page', () => page.press(keyTarget, 'Shift', { timeout: 5000 }));
  const other = pages.find((p) => p !== page && !p.isClosed());
  const raw = (p) => rawClick.get(p) || p.click.bind(p);
  if (other) await timed('click_other_page', () => raw(other)('nav button[data-view=contacts]', { timeout: 5000 }));
  await timed('bring_to_front', () => page.bringToFront());
  await timed('same_click_again', () => raw(page)(selector, { timeout: 5000, trial: true }));
  return out;
}

/** The contacts screen is up and the relay is bound (after a reload too). */
export async function ready(page) {
  await page.waitForSelector('#view-contacts:not(.hidden)');
  await page.waitForFunction(() => window.dsip && window.dsip.relay(), null, { timeout: 15000 });
}

export const until = (page, fn, arg = null, timeout = 20000) => page.waitForFunction(fn, arg, { timeout });
export const state = (p) => p.page.evaluate(() => window.dsip.state());
export const logOf = (p) => p.page.textContent('#log');

/** Add `other` as a contact on `p`'s contacts screen. */
export async function addContact(p, other) {
  await p.page.fill('#contact-name', other.name);
  await p.page.fill('#contact-did', other.did);
  await submit(p.page, 'contact-add');
  await p.page.waitForFunction((did) => window.dsip.contacts().includes(did), other.did);
}

/** Click the first button labelled `label` in `other`'s contact row. */
export async function rowButton(p, other, label) {
  const row = p.page.locator('#contact-list li', { has: p.page.locator(`code.did:text-is("${other.did}")`) });
  await row.locator(`button:text-is("${label}")`).click();
}

/** On failure: the last lines of everyone's log, so the cause is in the test output. */
export async function dump(...people) {
  for (const p of people) {
    if (!p) continue;
    const lines = (await p.page.textContent('#log').catch(() => '')).trim().split('\n');
    console.log(`--- ${p.name} (${await p.page.evaluate(() => window.dsip.state()).catch(() => '?')}) note: ${await p.page.evaluate(() => window.dsip.note()).catch(() => '')}`);
    // whether this page's main thread was ever held, and for how long (the heartbeat of openPage): a hung click
    // with a long max_gap_ms is the page; with a short one it is the browser or the driver
    const d = await pageDiag(p.page);
    console.log(`    page: ${d.unresponsive || d.evaluate_error || `max_gap_ms=${d.max_gap_ms} since_beat_ms=${d.since_beat_ms} view=${d.view} focused=${d.focused}`}`);
    for (const l of lines.slice(-(process.env.DUMP_ALL ? 999 : 14))) console.log('   ' + l);
  }
}

/** Click Call in `other`'s contact row on `p`. The contact list re-renders on many events, and a click that lands
 *  mid-render places no call, so confirm one started and click once more if not. */
export async function placeCall(p, other) {
  await rowButton(p, other, 'Call');
  if (!(await until(p.page, () => window.dsip.state() !== null, null, 3000).then(() => true, () => false))) {
    console.log(`  note: ${p.name}'s Call click placed no call; clicking again`);
    await rowButton(p, other, 'Call');
  }
}
