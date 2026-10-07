// Browser e2e : the page in headless Chrome with a virtual authenticator (a passkey with user verification), the
// real pam_web.so through pamtester. Run by scripts/e2e-browser.sh, which sets up PAM first.
import {spawn} from 'child_process'
import {writeFileSync} from 'fs'
import {connect, createServer} from 'net'
import {chromium} from 'playwright'

const SERVER = new URL(process.env.SERVER ?? 'http://localhost:5199')
/// WebAuthn needs a secure context (https or localhost) : the browser and pamtester (scripts/e2e-browser.sh) both
/// go through this local forward to the server, so the passkeys' site is localhost on both sides
const LOCAL = 'http://localhost:5199'
const forward = createServer(client => {
  const server = connect(Number(SERVER.port || 80), SERVER.hostname)
  client.pipe(server).pipe(client)
  // Like a proxy (Traefik) : one side gone, both connections closed, no half-close
  for (const [a, b] of [
    [client, server],
    [server, client]
  ]) {
    a.on('end', () => b.destroy())
    a.on('close', () => b.destroy())
    a.on('error', () => b.destroy())
  }
})
if (SERVER.host !== 'localhost:5199') await new Promise(done => forward.listen(5199, 'localhost', done))

function fail(message) {
  throw new Error(`FAIL : ${message}`)
}

const browser = await chromium.launch()
const page = await browser.newPage()
const cdp = await page.context().newCDPSession(page)
await cdp.send('WebAuthn.enable')
await cdp.send('WebAuthn.addVirtualAuthenticator', {
  options: {
    protocol: 'ctap2',
    transport: 'internal',
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true
  }
})

try {
  await page.goto(LOCAL)

  console.log('--- register a passkey on the page')
  await page.getByText('Set up a machine').click()
  await page.getByPlaceholder('Name, e.g. MacBook Touch ID').fill('ci')
  await page.getByRole('button', {name: 'Register'}).click()
  const config = page.locator('pre', {hasText: /^user /})
  await config.filter({hasText: /\nkey (es256|ed25519) /}).waitFor({timeout: 10_000})
  // The page's own config block, as the user would copy it
  writeFileSync('/etc/pam_web/root', (await config.textContent()) + '\n', {mode: 0o600})

  /// pamtester in the background : its exit code, and the code it showed
  function sudo() {
    const child = spawn('stdbuf', ['-oL', 'pamtester', 'pamweb', 'root', 'authenticate'])
    let output = ''
    child.stdout.on('data', d => (output += d))
    child.stderr.on('data', d => (output += d))
    const exit = new Promise(done => child.on('exit', status => done(status)))
    const code = (async () => {
      for (let i = 0; i < 100; i++) {
        const match = output.match(/code (\d{6})/)
        if (match) return match[1]
        await new Promise(r => setTimeout(r, 100))
      }
      fail(`no code shown : ${output}`)
    })()
    return {exit, code, output: () => output, kill: () => child.kill('SIGKILL')}
  }

  /// A request until its card shows on the page : the card, the terminal's code, and whether it's typed mode
  async function request() {
    const run = sudo()
    const code = await run.code
    const card = page.locator('li', {hasText: 'pamweb on'})
    await card.waitFor({timeout: 10_000})
    const typed = (await card.locator('input').count()) > 0
    if (!typed && !(await card.textContent()).includes(`${code.slice(0, 3)} ${code.slice(3)}`))
      fail('the card shows another code than the terminal')
    return {...run, code, card, typed}
  }

  async function expect_status(run, expected, what) {
    const status = await Promise.race([run.exit, new Promise(r => setTimeout(() => r('timeout'), 20_000))])
    if ((status === 0) !== expected) fail(`${what} : pamtester ${status} : ${run.output()}`)
    // The card is gone once answered
    await run.card.waitFor({state: 'detached', timeout: 10_000})
  }

  console.log('--- approved, in both modes (typed : 1 in 3, random)')
  const seen = new Set()
  for (let i = 0; seen.size < 2; i++) {
    if (i >= 40) fail('only one mode in 40 requests')
    const run = await request()
    seen.add(run.typed)
    if (run.typed) await run.card.locator('input').fill(run.code)
    await run.card.getByRole('button', {name: 'Authorize'}).click()
    await expect_status(run, true, `approval (typed : ${run.typed})`)
  }

  console.log('--- wrong typed code')
  for (let i = 0; ; i++) {
    if (i >= 40) fail('no typed mode in 40 requests')
    const run = await request()
    if (!run.typed) {
      await run.card.getByRole('button', {name: 'Refuse'}).click()
      await expect_status(run, false, 'refusal')
      continue
    }
    await run.card.locator('input').fill(String((Number(run.code) + 1) % 1_000_000).padStart(6, '0'))
    await run.card.getByRole('button', {name: 'Authorize'}).click()
    await expect_status(run, false, 'wrong typed code')
    break
  }

  console.log('--- cancelled sudo : the card goes away')
  const cancelled = await request()
  cancelled.kill()
  const killed = await Promise.race([cancelled.exit, new Promise(r => setTimeout(() => r('alive'), 5_000))])
  if (killed === 'alive') fail('pamtester still running after SIGKILL')
  await cancelled.card
    .waitFor({state: 'detached', timeout: 10_000})
    .catch(() => fail(`the card stayed after pamtester died (exit ${killed}) : the server missed the disconnect`))

  console.log('--- refused')
  const run = await request()
  await run.card.getByRole('button', {name: 'Refuse'}).click()
  await expect_status(run, false, 'refusal')

  console.log('OK')
} catch (e) {
  await page.screenshot({path: '/tmp/e2e-browser.png', fullPage: true}).catch(() => {})
  console.error(e.message, '(screenshot : /tmp/e2e-browser.png)')
  process.exitCode = 1
} finally {
  await browser.close()
  forward.close()
}
