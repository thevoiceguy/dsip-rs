// Headless first-contact test (stage 2): a stranger's call is refused until introduced; introductions, requests with
// their purpose, grants, screening with escalation, a contact link that grants at once, and an ignored introduction.
import { launch, person, ready, until, state, logOf, addContact, rowButton, checker, dump, which } from './lib.mjs';

const check = checker();
const browser = await launch();
let alice, bob;
try {
  alice = await person(browser, 'Alice');
  bob = await person(browser, 'Bob');

  // Bob requires first contact (the setting reloads the page)
  await bob.page.click('nav button[data-view=settings]');
  // the change handler reloads the page, so click without waiting for the post-click state and wait for the load
  await Promise.all([bob.page.waitForNavigation({ waitUntil: 'load' }), bob.page.click('#set-first-contact', { noWaitAfter: true })]);
  await ready(bob.page);
  await bob.page.click('nav button[data-view=settings]');
  check('Bob: first contact required is on after the reload', await bob.page.isChecked('#set-first-contact'));
  await bob.page.click('nav button[data-view=contacts]');

  // Alice, a stranger, calls: refused without ringing; she is told to introduce herself
  await addContact(alice, bob);
  await rowButton(alice, bob, 'Call');
  await until(alice.page, () => window.dsip.state() === null);
  check('Alice: the call ends with the first-contact guidance', /require an introduction/.test(await alice.page.evaluate(() => window.dsip.note())), await alice.page.evaluate(() => window.dsip.note()));
  check('Alice: an Introduce button is offered', await alice.page.isVisible('#btn-introduce-after'));
  check('Bob: nothing rang', !(await bob.page.isVisible('#view-incoming')) && /refused a call .* first contact required/.test(await logOf(bob)));

  // Alice introduces herself with a purpose
  await alice.page.click('#btn-introduce-after');
  await alice.page.waitForSelector('#introduce-form:not(.hidden)');
  check('Alice: the introduce form names Bob', (await alice.page.textContent('#introduce-did')) === bob.did);
  await alice.page.fill('#introduce-purpose', 'Lunch on Friday?');
  await alice.page.click('#introduce-form button[type=submit]');
  await until(alice.page, (did) => window.dsip.contactStatus(did) === 'introduction sent, waiting', bob.did);
  check('Alice: contact shows the introduction pending', true);

  // Bob sees a request with the purpose and the basis; grants it
  await until(bob.page, () => window.dsip.requests().length === 1);
  const reqText = await bob.page.textContent('#request-list');
  check('Bob: the request shows who, the purpose as a claim, and the basis', reqText.includes(alice.did) && reqText.includes('Lunch on Friday?') && reqText.includes('Self-issued'), reqText.replace(/\s+/g, ' ').slice(0, 160));
  check('Bob: an introduction never rings', !(await bob.page.isVisible('#view-incoming')) && (await state(bob)) === null);
  await bob.page.click('#request-list button:text-is("Grant")');
  await until(alice.page, (did) => window.dsip.contactStatus(did) === 'they granted you', bob.did);
  check('Alice: holds the grant', true);
  await until(bob.page, () => window.dsip.requests().length === 0);

  // Now the call rings; Bob screens, then answers for real
  await rowButton(alice, bob, 'Call');
  await bob.page.waitForSelector('#view-incoming:not(.hidden)');
  check('Bob: the incoming screen says the caller is granted', /granted/.test(await bob.page.textContent('#in-contact')), await bob.page.textContent('#in-contact'));
  await bob.page.click('#btn-screen');
  await until(alice.page, () => window.dsip.state() === 'ACTIVE');
  await until(bob.page, () => window.dsip.state() === 'ACTIVE');
  await until(alice.page, () => /screening/.test(window.dsip.note()));
  check('Alice: told the call was answered in screening mode (§14.4)', true);
  check('Bob: can answer for real', await bob.page.isVisible('#btn-escalate'));
  await bob.page.click('#btn-escalate');
  await until(alice.page, () => document.getElementById('btn-answer-update').offsetParent !== null);
  check('Alice: the escalation arrives as an update to answer', true);
  await alice.page.click('#btn-answer-update');
  await until(bob.page, () => /media apply_update/.test(document.getElementById('log').textContent));
  check('Bob: the escalation is applied', true);
  await alice.page.click('#btn-hangup');
  await until(bob.page, () => window.dsip.state() === null);
  await until(alice.page, () => window.dsip.state() === null);

  // A contact link: Carol opens it and is granted without a request
  await bob.page.click('nav button[data-view=settings]');
  await bob.page.click('#btn-contact-link');
  await until(bob.page, () => window.dsip.links().length === 1);
  const link = (await bob.page.evaluate(() => window.dsip.links()))[0];
  check('Bob: the link names Bob and carries a token', link.includes(encodeURIComponent(bob.did)) && /token=[A-Za-z0-9_-]{20,}/.test(link));
  const carol = await person(browser, 'Carol', link);
  await until(bob.page, () => /used your contact link: granted/.test(document.getElementById('log').textContent));
  check('Bob: the token introduction was granted at once', (await bob.page.evaluate(() => window.dsip.requests())).length === 0 && (await bob.page.evaluate(() => window.dsip.contacts())).includes(carol.did));
  await until(carol.page, (did) => window.dsip.contactStatus(did) === 'they granted you', bob.did);
  check('Carol: holds the grant, Bob in her contacts', true);
  await bob.page.click('nav button[data-view=settings]');
  check('Bob: the link shows as used', /used/.test(await bob.page.textContent('#contact-links')) && !/unused/.test(await bob.page.textContent('#contact-links')));
  await bob.page.click('nav button[data-view=contacts]');
  await rowButton(carol, bob, 'Call');
  await bob.page.waitForSelector('#view-incoming:not(.hidden)');
  check('Carol: her call rings at Bob', true);
  await bob.page.click('#btn-decline');
  await until(carol.page, () => window.dsip.state() === null);

  // Dave introduces himself; Bob ignores
  const dave = await person(browser, 'Dave');
  await addContact(dave, bob);
  await rowButton(dave, bob, 'Introduce');
  await dave.page.fill('#introduce-purpose', 'Selling something');
  await dave.page.click('#introduce-form button[type=submit]');
  await until(bob.page, () => window.dsip.requests().length === 1);
  await bob.page.click('#request-list button:text-is("Ignore")');
  await until(dave.page, () => /introduction of yours was declined/.test(document.getElementById('log').textContent));
  check('Dave: told the introduction was declined', true);
  await until(bob.page, () => window.dsip.requests().length === 0);

  // a reload keeps the requests surface working: Eve introduces, Bob reloads, then grants
  const eve = await person(browser, 'Eve');
  await addContact(eve, bob);
  await rowButton(eve, bob, 'Introduce');
  await eve.page.fill('#introduce-purpose', 'Old friend');
  await eve.page.click('#introduce-form button[type=submit]');
  await until(bob.page, () => window.dsip.requests().length === 1);
  await bob.page.reload();
  await ready(bob.page);
  check('Bob: the request survives a reload with its purpose', (await bob.page.evaluate(() => window.dsip.requests())).length === 1 && (await bob.page.textContent('#request-list')).includes('Old friend'));
  await bob.page.click('#request-list button:text-is("Grant")');
  await until(eve.page, (did) => window.dsip.contactStatus(did) === 'they granted you', bob.did);
  check('Eve: granted after Bob\'s reload', true);
} catch (e) {
  check.fail(e.message);
  await dump(alice, bob);
} finally {
  await browser.close();
}
console.log(`\n${which} first-contact: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
