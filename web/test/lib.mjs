// Shared by the headless tests: launch a browser with fake media, make a person (a fresh storage context, so a fresh
// identity), and small waits. Env: BROWSER=firefox|chromium, URL=https://127.0.0.1:8443/.
import { chromium, firefox } from 'playwright';

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
      '--disable-features=WebRtcHideLocalIpsWithMdns', '--ignore-certificate-errors'] });
  }
  return firefox.launch({ headless: true, firefoxUserPrefs: {
    'media.navigator.streams.fake': true, 'media.navigator.permission.disabled': true,
    'media.peerconnection.ice.obfuscate_host_addresses': false, 'network.websocket.allowInsecureFromHTTPS': true,
  } });
}

/** A fresh browser context (fresh storage, so a fresh identity) with a page at `url`, on the welcome screen. */
export async function openPage(browser, name, url = URL) {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, permissions: which === 'chromium' ? ['camera', 'microphone'] : [] });
  const page = await ctx.newPage();
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
  await p.page.click('#contact-add button[type=submit]');
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
    for (const l of lines.slice(-(process.env.DUMP_ALL ? 999 : 14))) console.log('   ' + l);
  }
}
