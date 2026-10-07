// The production build has no dev shortcut : no dev user, no dev token key. Run after `npm run build`.
import {spawn} from 'child_process'
import {createHmac, randomBytes} from 'crypto'
import {mkdtempSync, writeFileSync} from 'fs'
import {tmpdir} from 'os'
import {join} from 'path'

const PORT = 3990
const URL = `http://localhost:${PORT}`

function fail(message) {
  throw new Error(`FAIL : ${message}`)
}

function serve(key_file) {
  return spawn(process.execPath, ['node_modules/@react-router/serve/bin.js', 'build/server/index.js'], {
    env: {...process.env, PORT: String(PORT), TOKEN_KEY_FILE: key_file},
    stdio: 'ignore'
  })
}

console.log('--- no key file : the server refuses to start')
const keyless = serve('/nonexistent/pam_token_key')
const status = await Promise.race([
  new Promise(done => keyless.on('exit', done)),
  new Promise(done => setTimeout(() => done('still running'), 10_000))
])
keyless.kill()
if (status === 'still running' || status === 0) {
  console.error(`FAIL : started without its key (${status})`)
  process.exit(1)
}

let server
try {
  const dir = mkdtempSync(join(tmpdir(), 'pam_web_'))
  const key_file = join(dir, 'pam_token_key')
  writeFileSync(key_file, randomBytes(32))
  server = serve(key_file)
  for (let i = 0; ; i++) {
    if (i >= 60) fail('the server never answered')
    if (
      await fetch(`${URL}/api/health`).then(
        r => r.ok,
        () => false
      )
    )
      break
    await new Promise(r => setTimeout(r, 500))
  }

  console.log('--- no Remote-User : no dev user, 401')
  for (const path of ['/', '/api/authorization/list?known=x']) {
    const res = await fetch(URL + path, {redirect: 'manual'})
    if (res.status !== 401) fail(`${path} without Remote-User : ${res.status}`)
  }

  console.log('--- Remote-User : the page')
  const page = await fetch(URL, {headers: {'Remote-User': 'alice'}})
  if (page.status !== 200 || !(await page.text()).includes('alice')) fail(`page with Remote-User : ${page.status}`)

  console.log("--- the dev user's token (dev key) is refused")
  const dev_token = createHmac('sha256', 'dev').update('dev').digest('hex')
  const res = await fetch(`${URL}/api/authorization/request`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      user: 'dev',
      token: dev_token,
      nonce: 'ab'.repeat(32),
      ts: 0,
      uid: 0,
      pam_user: 'root',
      ruser: null,
      service: 'sudo',
      tty: null,
      rhost: null,
      cmdline: [],
      hostname: 'x'
    })
  })
  if (res.status !== 403) fail(`dev token : ${res.status}`)

  console.log('OK')
} catch (e) {
  console.error(e.message)
  process.exitCode = 1
} finally {
  server?.kill()
}
