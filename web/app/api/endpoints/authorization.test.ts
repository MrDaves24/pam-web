import {afterEach, expect, test, vi} from 'vitest'

import app from '@/api'
import {DEV_USER, request_token} from '@/helpers/user.server'
import {get_list_for_user, LIST_TIMEOUT, RATE_LIMIT, TIMEOUT, waiting} from '@/api/endpoints/authorization'

const USER = DEV_USER
const OTHER = 'other'

/// `signal` : aborting it is the connection closing
const call = (
  path: string,
  method = 'GET',
  body?: object | string,
  headers: Record<string, string> = {},
  signal?: AbortSignal
) =>
  app.handle(
    new Request(`http://localhost/api/authorization${path}`, {
      method,
      headers: {'Content-Type': 'application/json', ...headers},
      body: typeof body === 'object' ? JSON.stringify(body) : body,
      signal
    })
  )
/// A new client IP each time, so tests don't share a rate limit
let ip = 0
const new_ip = () => ({'X-Forwarded-For': `10.0.${Math.floor(++ip / 250)}.${ip % 250}`})
const authorize = (challenge: string, body: object = ASSERTION) => call(`/authorize/${challenge}`, 'POST', body)
const block = (challenge: string) => call(`/block/${challenge}`, 'POST')

/// The server only relays it, the PAM client checks it
const ASSERTION = {authenticator_data: 'YXV0aA==', client_data_json: 'e30=', signature: 'c2ln'}

/// What the PAM client sends
const body = (user = USER) => ({
  user,
  token: request_token(user),
  nonce: 'ab'.repeat(32),
  ts: 1759752000,
  uid: 1000,
  pam_user: 'alice',
  ruser: null,
  service: 'sudo',
  tty: '/dev/pts/1',
  rhost: null,
  cmdline: ['sudo', 'apt', 'update'],
  hostname: 'server',
  code: '042137'
})

/// Create a request (PAM side) and wait until the server registered it
async function request(user = USER, raw = JSON.stringify(body(user)), headers: Record<string, string> = new_ip()) {
  const before = get_list_for_user(user)
  const response = call('/request', 'POST', raw, headers)
  await vi.waitFor(() => expect(get_list_for_user(user)).toHaveLength(before.length + 1))
  const challenge = get_list_for_user(user).at(-1)!.challenge
  return {challenge, response}
}

const challenges = (user = USER) => get_list_for_user(user).map(r => r.challenge)

afterEach(() => vi.useRealTimers())

test('authorize relays the assertion and removes only that challenge', async () => {
  const a = await request()
  const b = await request()

  expect((await authorize(a.challenge)).status).toBe(200)
  const res = await a.response
  expect(res.status).toBe(200)
  expect(await res.json()).toEqual(ASSERTION)
  expect(challenges()).toEqual([b.challenge])

  // Already answered
  expect((await authorize(a.challenge)).status).toBe(400)

  await block(b.challenge)
  expect((await b.response).status).toBe(403)
  expect(challenges()).toEqual([])
})

test("can't answer another user's challenge", async () => {
  vi.useFakeTimers()
  const other = await request(OTHER)
  expect((await authorize(other.challenge)).status).toBe(400)
  expect(challenges(OTHER)).toEqual([other.challenge])

  // Cleanup
  await vi.advanceTimersByTimeAsync(TIMEOUT)
})

test('timeout blocks and removes the challenge', async () => {
  vi.useFakeTimers()
  const {challenge, response} = await request()

  await vi.advanceTimersByTimeAsync(TIMEOUT)
  expect((await response).status).toBe(403)
  expect(challenges()).toEqual([])
  expect((await authorize(challenge)).status).toBe(400)
})

test('waiting browsers get the full list on every change', async () => {
  const first = call('/list?known=')
  const a = await request()
  expect((await (await first).json()).map((r: {challenge: string}) => r.challenge)).toEqual([a.challenge])

  const second = call(`/list?known=${a.challenge}`)
  await block(a.challenge)
  expect(await (await second).json()).toEqual([])
  await a.response
})

test('outdated browser list is answered right away', async () => {
  const a = await request()
  // The browser missed `a` (it was created between two polls)
  expect((await (await call('/list?known=')).json()).map((r: {challenge: string}) => r.challenge)).toEqual([a.challenge])
  await block(a.challenge)
  await a.response
})

test('the exact body is kept, for the browser to sign', async () => {
  // Not what JSON.stringify would give back : no re-serialization
  const raw = JSON.stringify(body(), null, 3)
  const a = await request(USER, raw)
  expect(get_list_for_user(USER)).toEqual([{challenge: a.challenge, raw}])
  await block(a.challenge)
  await a.response
})

test('invalid bodies are rejected', async () => {
  for (const bad of [
    {...body(), user: 'x'.repeat(1000)},
    {...body(), token: 'short'},
    {...body(), token: undefined},
    {...body(), nonce: 'short'},
    {...body(), code: '12345'},
    {...body(), cmdline: 'sudo -s'},
    {...body(), hostname: 'x'.repeat(1000)}
  ]) {
    expect([400, 422]).toContain((await call('/request', 'POST', bad, new_ip())).status)
  }
  expect([400, 422]).toContain((await call('/request', 'POST', 'not json', new_ip())).status)
  expect(challenges()).toEqual([])
})

test('typed mode : no code', async () => {
  const {code, ...typed} = body()
  expect(code).toBeDefined()
  const a = await request(USER, JSON.stringify(typed))
  await block(a.challenge)
  expect((await a.response).status).toBe(403)
})

test('invalid assertions are rejected, the request stays pending', async () => {
  const a = await request()
  for (const bad of [{}, {...ASSERTION, signature: 'not base64!'}, {...ASSERTION, signature: 'A'.repeat(5000)}]) {
    expect([400, 422]).toContain((await authorize(a.challenge, bad)).status)
  }
  expect(challenges()).toEqual([a.challenge])
  await block(a.challenge)
  await a.response
})

test('timeout is shorter than the PAM client', () => {
  // pam/src/lib.rs : TIMEOUT
  expect(TIMEOUT).toBeLessThan(60_000)
})

test('rate limit per IP, from the last X-Forwarded-For entry', async () => {
  vi.useFakeTimers()
  // Anything before Traefik's entry is what the client claimed
  const spoofed = (n: number) => ({'X-Forwarded-For': `1.2.3.${n}, 192.0.2.1`})
  const created = []
  for (let n = 0; n < RATE_LIMIT; n++) created.push(await request(USER, undefined, spoofed(n)))
  expect((await call('/request', 'POST', body(), spoofed(99))).status).toBe(429)
  // Another IP isn't limited
  created.push(await request())
  // Not through Traefik (dev) : not limited
  for (let n = 0; n <= RATE_LIMIT; n++) created.push(await request(USER, undefined, {}))

  await vi.advanceTimersByTimeAsync(TIMEOUT)
  for (const {response} of created) expect((await response).status).toBe(403)
  // A minute later, allowed again
  await vi.advanceTimersByTimeAsync(60_000)
  const again = await request(USER, undefined, spoofed(0))
  await block(again.challenge)
  await again.response
})

test('answers from another site are refused', async () => {
  const a = await request()
  for (const origin of ['https://evil.example', 'null']) {
    expect((await call(`/block/${a.challenge}`, 'POST', undefined, {Origin: origin})).status).toBe(403)
    expect((await call(`/authorize/${a.challenge}`, 'POST', ASSERTION, {Origin: origin})).status).toBe(403)
  }
  expect(challenges()).toEqual([a.challenge])
  // Our own page
  expect((await call(`/block/${a.challenge}`, 'POST', undefined, {Origin: 'http://localhost'})).status).toBe(200)
  expect((await a.response).status).toBe(403)
})

test('a wrong request token is refused, nothing reaches the browser', async () => {
  vi.useFakeTimers()
  for (const token of [request_token(OTHER), 'f'.repeat(64)]) {
    expect((await call('/request', 'POST', {...body(), token}, new_ip())).status).toBe(403)
  }
  // Right token, other user : only that user's browser sees it
  const other = await request(OTHER)
  expect(challenges()).toEqual([])
  expect(challenges(OTHER)).toEqual([other.challenge])
  await vi.advanceTimersByTimeAsync(TIMEOUT)
  expect(challenges(OTHER)).toEqual([])
})

test('a cancelled sudo disappears from the page', async () => {
  const connection = new AbortController()
  const response = call('/request', 'POST', body(), new_ip(), connection.signal)
  await vi.waitFor(() => expect(challenges()).toHaveLength(1))
  const challenge = challenges()[0]

  // The waiting browser is told
  const browser = call(`/list?known=${challenge}`)
  connection.abort()
  expect(await (await browser).json()).toEqual([])
  expect(challenges()).toEqual([])
  expect((await authorize(challenge)).status).toBe(400)
  await response.catch(() => {})
})

test('a held list answers after LIST_TIMEOUT even without a change', async () => {
  vi.useFakeTimers()
  const held = call('/list?known=')
  await vi.waitFor(() => expect(waiting(USER)).toBe(1))
  await vi.advanceTimersByTimeAsync(LIST_TIMEOUT)
  expect(await (await held).json()).toEqual([])
  expect(waiting(USER)).toBe(0)
})

test("a closed tab's waiter is dropped at once", async () => {
  const tab = new AbortController()
  const held = call('/list?known=', 'GET', undefined, {}, tab.signal)
  await vi.waitFor(() => expect(waiting(USER)).toBe(1))
  tab.abort()
  await vi.waitFor(() => expect(waiting(USER)).toBe(0))
  await held.catch(() => {})
})

test('a PAM client gone before its request is handled leaves nothing behind', async () => {
  const connection = new AbortController()
  connection.abort()
  const response = await call('/request', 'POST', body(), new_ip(), connection.signal).catch(() => null)
  await vi.waitFor(() => expect(challenges()).toEqual([]))
  if (response) expect(response.status).toBe(403)
})
