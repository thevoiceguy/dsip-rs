// Presence audiences and time-boxed shares (Presence Profile draft, P§6, P§7): Bob's browser publishes his presence,
// available, and a second record for his `family` audience, busy, each signed by itself. He grants Alice the family
// audience and Carol a short share with none. Alice sees busy (both records, combined, P§4); Carol sees only the record
// with no audience. A change to the family state reaches Alice and not Carol. At the end of Carol's share Bob's relay
// ends her watch (policy.terminated) and she shows nothing. Last, Bob changes Alice's grant with a grant that follows
// it (spec-gap 150): to calls only, which ends her watch while she stays granted, then back to presence with no audience,
// which she watches again without introducing herself. Run by test/run.sh.
import { launch, person, until, checker, dump, addContact, rowButton, submit, sleep, which } from './lib.mjs';

const check = checker();
const SHARE_S = 30;
const shown = (p, other) => p.page.evaluate((did) => window.dsip.presence(did), other.did);
const shows = (p, other, fn, timeout = 30000) => p.page.waitForFunction(([did, f]) => {
  const v = window.dsip.presence(did);
  return v && new Function('v', `return ${f}`)(v);
}, [other.did, fn], { timeout }).then(() => true, () => false);

/** `from` introduces itself to `to`, who grants it with the request row's audience and length set by `choose`. */
async function granted(from, to, choose) {
  await rowButton(from, to, 'Introduce');
  await from.page.fill('#introduce-purpose', 'audiences');
  await submit(from.page, 'introduce-form');
  await until(to.page, () => window.dsip.requests().length >= 1, null, 30000);
  await choose(to.page.locator('#request-list li').first());
  await to.page.click('#request-list button:text-is("Grant")');
  await until(from.page, (did) => window.dsip.contactStatus(did) === 'they granted you', to.did, 30000);
  await from.page.evaluate((did) => window.dsip.watchPresence(did), to.did);
}

const browser = await launch();
let alice, bob, carol;
try {
  [alice, bob, carol] = [await person(browser, 'Alice'), await person(browser, 'Bob'), await person(browser, 'Carol')];
  for (const [a, b] of [[alice, bob], [bob, alice], [carol, bob], [bob, carol]]) await addContact(a, b);

  await bob.page.evaluate(() => window.dsip.setPresence('available'));
  await bob.page.click('nav button[data-view=settings]');
  await bob.page.fill('#audience-name', 'family');
  await bob.page.selectOption('#audience-state', 'busy');
  await submit(bob.page, 'audience-form');
  await bob.page.click('nav button[data-view=contacts]');
  await until(bob.page, () => /→ presence +busy for audience family seq/.test(document.getElementById('log').textContent), null, 15000);
  check('Bob\'s browser signs a second record, for his family audience (P§6)',
    /→ presence +available seq/.test(await bob.page.textContent('#log')) && (await bob.page.evaluate(() => window.dsip.audiences())).family === 'busy');

  await granted(alice, bob, (row) => row.locator('select.grant-audience').selectOption('family'));
  await granted(carol, bob, async (row) => {
    // a share shorter than the picker offers, so the test sees it end (P§7)
    await row.locator('select.grant-length').evaluate((sel, s) => sel.append(new Option(`for ${s} s`, String(s))), SHARE_S);
    await row.locator('select.grant-length').selectOption(String(SHARE_S));
  });
  const shareEnds = Date.now() + SHARE_S * 1000;
  check('Bob\'s contact rows say what he shares: family with Alice, a share with an end with Carol (P§6, P§7)',
    /family/.test(await bob.page.evaluate((d) => window.dsip.contactStatus(d), alice.did))
    && /until/.test(await bob.page.evaluate((d) => window.dsip.contactStatus(d), carol.did)),
    `${await bob.page.evaluate((d) => window.dsip.contactStatus(d), alice.did)} | ${await bob.page.evaluate((d) => window.dsip.contactStatus(d), carol.did)}`);

  check('Alice, in family, sees busy: his family record and his main one, combined (P§4, P§6)',
    await shows(alice, bob, "v.source === 'record' && v.state === 'busy'"), JSON.stringify(await shown(alice, bob)));
  check('Carol, with no audience, sees only his main record: available (P§6)',
    await shows(carol, bob, "v.source === 'record' && v.state === 'available'"), JSON.stringify(await shown(carol, bob)));

  await sleep(5500);   // P§8: the family record's publish interval
  await bob.page.evaluate(() => window.dsip.setAudience('family', 'dnd'));
  check('Bob sets family to do not disturb: Alice sees it (P§6)',
    await shows(alice, bob, "v.state === 'dnd'", 20000), JSON.stringify(await shown(alice, bob)));
  check('and Carol still sees available', (await shown(carol, bob))?.state === 'available', JSON.stringify(await shown(carol, bob)));

  await sleep(Math.max(0, shareEnds - Date.now()));
  check('Carol\'s share ends at its valid_until: Bob\'s relay ends her watch and she shows nothing (P§7)',
    await carol.page.waitForFunction((did) => window.dsip.presence(did) === null, bob.did, { timeout: 20000 }).then(() => true, () => false)
    && /they stopped sharing it with us/.test(await carol.page.textContent('#log')), JSON.stringify(await shown(carol, bob)));
  check('Alice still sees Bob (her grant lasts)', (await shown(alice, bob))?.state === 'dnd', JSON.stringify(await shown(alice, bob)));

  /** Bob opens the grant editor on Alice's row and applies it with `presence` and `audience`. */
  const change = async (presence, audience) => {
    const row = bob.page.locator('#contact-list li', { has: bob.page.locator(`code.did:text-is("${alice.did}")`) });
    await row.locator('button:text-is("Change grant")').click();
    const box = row.locator('.grant-edit');
    await box.locator('select.grant-audience').selectOption(audience);
    await box.locator('input.grant-presence').setChecked(presence);
    // another row's change rebuilds the list (Carol's share has just ended): the open editor and its picks survive it
    await bob.page.evaluate(() => window.dsip.rebuildContacts());
    check('Bob\'s open grant editor survives the contact list being rebuilt, picks kept',
      await box.locator('input.grant-presence').isChecked({ timeout: 2000 }).then((v) => v === presence, () => false)
      && await box.locator('select.grant-audience').inputValue({ timeout: 2000 }).then((v) => v === audience, () => false));
    await box.locator('button:text-is("Apply")').click();
    check('Apply closes the editor', await row.locator('.grant-edit').count() === 0);
  };
  await change(false, '');
  check('Calls only: a grant follows Alice\'s, the old one revoked at Bob\'s relay; her watch ends (§19.4, P§7)',
    await alice.page.waitForFunction((did) => window.dsip.presence(did) === null, bob.did, { timeout: 20000 }).then(() => true, () => false)
    && /→ grant-revocation of our grant [^\n]*\n(?:[^\n]*\n)*?[^\n]*→ grant /.test(await bob.page.textContent('#log')), JSON.stringify(await shown(alice, bob)));
  check('Alice still holds a grant from Bob: she need not introduce herself again (spec-gap 150)',
    /granted you|mutual grant/.test(await alice.page.evaluate((d) => window.dsip.contactStatus(d), bob.did) || ''),
    await alice.page.evaluate((d) => window.dsip.contactStatus(d), bob.did));
  await sleep(1500);   // the next change revokes the grant just issued: let it reach Alice first
  await change(true, '');
  check('Presence again, no audience: Alice watches again with the new grant and sees his main record, available (P§6)',
    await shows(alice, bob, "v.source === 'record' && v.state === 'available'", 30000), JSON.stringify(await shown(alice, bob)));
} catch (e) {
  check.fail(e.message);
  await dump(...[alice, bob, carol].filter(Boolean));
}
await browser.close();
console.log(`\n${which} presence-audiences: ${check.failures()} failure(s)`);
process.exit(check.failures() ? 1 : 0);
