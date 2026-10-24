// One device, two tabs (§13.2, spec-gap 158): a second tab of the same browser profile holds the same device key, so its
// hello replaces the first tab's connection at the relay. The relay says `transport.replaced` on the old connection; the
// first tab stops instead of reconnecting (which would replace the second in turn, and so on), and says why. The second
// tab stays bound. Run by test/run.sh.
import { launch, person, ready, until, checker, dump, sleep, URL, which } from './lib.mjs';

const check = checker();
const binds = (page) => page.evaluate(() => (document.getElementById('log').textContent.match(/← hello {8}relay .* bound/g) || []).length);

const browser = await launch();
let alice;
try {
  alice = await person(browser, 'Alice');
  const first = alice.page;
  const second = await alice.ctx.newPage();
  second.on('pageerror', (e) => console.log(`  [Alice, tab 2] page error: ${e.message}`));
  await second.goto(URL);
  await ready(second);
  check('the second tab is the same device, bound at the relay', (await second.evaluate(() => window.dsip.identity())) === alice.did);

  check('the first tab is told it was replaced (transport.replaced, §13.2)',
    await until(first, () => /connected to the relay elsewhere/.test(document.getElementById('relay-status').textContent), null, 15000)
      .then(() => true, () => false), await first.textContent('#relay-status'));
  await sleep(6000);   // several of the first tab's backoff steps (1 s, 2 s): it would have reconnected by now
  check('the first tab did not reconnect: it bound once', (await binds(first)) === 1, String(await binds(first)));
  check('the second tab is still bound, once', (await binds(second)) === 1 && !!(await second.evaluate(() => window.dsip.relay())),
    String(await binds(second)));
  check('the first tab still says why', /connected to the relay elsewhere/.test(await first.textContent('#relay-status')),
    await first.textContent('#relay-status'));
} catch (e) {
  check.fail(e.message);
  await dump(...[alice].filter(Boolean));
}
await browser.close();
console.log(`\n${which} relay-replaced: ${check.failures()} failure(s)`);
