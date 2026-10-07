import Elysia, {t} from 'elysia'

import middleware from '@/api/middlewares/user'
import {check_request_token} from '@/helpers/user.server'

const nullable = (schema: ReturnType<typeof t.String>) => t.Union([schema, t.Null()])
const text = (maxLength = 256) => t.String({maxLength})
const base64 = t.String({pattern: '^[A-Za-z0-9+/]*={0,2}$', maxLength: 4096})

/// What the PAM client sends (see pam/src/lib.rs, new_request)
const RequestBody = t.Object({
  /// The web (Authelia) user who approves, and its request token (shown on the page)
  user: text(),
  token: t.String({pattern: '^[0-9a-f]{64}$'}),
  nonce: t.String({pattern: '^[0-9a-f]{64}$'}),
  ts: t.Integer(),
  uid: t.Integer(),
  pam_user: text(),
  ruser: nullable(text()),
  service: nullable(text()),
  tty: nullable(text()),
  rhost: nullable(text()),
  cmdline: t.Array(text(4096), {maxItems: 256}),
  hostname: text(),
  /// Absent in typed mode : the user types it from the terminal
  code: t.Optional(t.String({pattern: '^[0-9]{6}$'}))
})
export type RequestContext = typeof RequestBody.static

/// The passkey's answer (navigator.credentials.get), relayed as is to the PAM client which checks it
const Assertion = t.Object({authenticator_data: base64, client_data_json: base64, signature: base64})
type AssertionBody = typeof Assertion.static

/// `raw` is the body exactly as the PAM client sent it : the browser signs these bytes
export type PendingRequest = {challenge: string; raw: string}

/// Pending authorization requests (challenge UUID => resolution function : the assertion, or null to block)
// eslint-disable-next-line no-unused-vars
const authorization_requests: Map<string, {callback: (result: AssertionBody | null) => void; user: string}> = new Map()
const requests_per_user: Map<string, PendingRequest[]> = new Map()
// eslint-disable-next-line no-unused-vars
const user_waiting: Map<string, ((list: PendingRequest[]) => void)[]> = new Map()

/// Waiting browsers of `user` (tests)
export const waiting = (user: string) => user_waiting.get(user)?.length ?? 0

/// A held /list answers by then even without a change : a connection dropped silently (proxy, network) is replaced
/// quickly, and no waiter outlives it
export const LIST_TIMEOUT = 25_000

export function get_list_for_user(user: string): PendingRequest[] {
  return requests_per_user.get(user) ?? []
}

/// Send the current list to every waiting browser of `user`
function notify(user: string) {
  const callbacks = user_waiting.get(user) ?? []
  user_waiting.delete(user)
  const list = get_list_for_user(user)
  for (const callback of callbacks) callback(list)
}

function remove(challenge: string, user: string) {
  authorization_requests.delete(challenge)
  const list = get_list_for_user(user).filter(r => r.challenge !== challenge)
  if (list.length === 0) requests_per_user.delete(user)
  else requests_per_user.set(user, list)
  notify(user)
}

function answer_callback(challenge: string, user: string, result: AssertionBody | null): boolean {
  const req = authorization_requests.get(challenge)
  if (req === undefined) {
    console.warn(`Can't find authorization request for challenge ${challenge}`)
    return false
  }

  if (req.user !== user) {
    console.error(`SUSPECT : User ${user} tried to answer challenge ${challenge}, owned by user ${req.user} !`)
    return false
  }

  req.callback(result)
  remove(challenge, user)

  return true
}

/// Shorter than the PAM client's (60 s) : the server always answers first
export const TIMEOUT = 55_000

/// Requests created per IP and per minute
export const RATE_LIMIT = 10
// ponytail: in memory, per process; entries live one minute
const recent_requests: Map<string, number[]> = new Map()

/// Whether `ip` may create a request now (and count it)
function rate_limit(ip: string): boolean {
  const now = Date.now()
  const recent = (recent_requests.get(ip) ?? []).filter(t => t > now - 60_000)
  if (recent.length >= RATE_LIMIT) return false
  recent_requests.set(ip, [...recent, now])
  return true
}

/// The client's IP : Traefik (the only one reaching us) sets X-Forwarded-For, its last entry is what it saw.
/// Null without it : not through Traefik (dev, e2e), not limited.
function client_ip(request: Request): string | null {
  return request.headers.get('x-forwarded-for')?.split(',').at(-1)?.trim() ?? null
}

/// `origin` can be anything, even "null" (sandboxed frames)
function same_host(origin: string, url: string): boolean {
  try {
    return new URL(origin).host === new URL(url).host
  } catch {
    return false
  }
}

export default new Elysia({prefix: '/authorization'})
  /// The PAM client asks for an authorization, answered once the user decided (or timed out)
  .post(
    '/request',
    async ({body: {raw, json: request}, status, request: http}) => {
      const {user} = request
      const ip = client_ip(http)
      if (ip !== null && !rate_limit(ip)) {
        console.warn(`Rate limit : ${ip} created more than ${RATE_LIMIT} requests in a minute`)
        throw status(429)
      }
      // After the rate limit : guessing tokens is limited too
      if (!check_request_token(user, request.token)) {
        console.warn(`Wrong request token for user ${user} from ${ip ?? 'direct'}`)
        throw status(403)
      }
      const challenge = crypto.randomUUID()
      console.info(`New challenge ${challenge} for user ${user} : ${request.pam_user}@${request.hostname} (${request.service})`)

      const authorization = new Promise<AssertionBody | null>(done => {
        console.debug(`Create promise to wait for authorization ${challenge}`)
        const to = setTimeout(() => {
          console.info(`Authorization ${challenge} timed out`)
          remove(challenge, user)
          done(null)
        }, TIMEOUT)
        const callback = (result: AssertionBody | null) => {
          console.info(`Request ${challenge}, ${result ? 'signed' : 'blocked'}`)
          clearTimeout(to)
          done(result)
        }
        authorization_requests.set(challenge, {callback, user})
        // The PAM client is gone (sudo cancelled) : nobody waits for an answer anymore, take it off the page.
        // The signal also aborts once the connection closes normally : by then the request is answered.
        const cancelled = () => {
          if (!authorization_requests.has(challenge)) return
          console.info(`Request ${challenge} cancelled by the PAM client`)
          clearTimeout(to)
          remove(challenge, user)
          done(null)
        }
        http.signal.addEventListener('abort', cancelled, {once: true})
        // Gone before we listened : the event won't come
        if (http.signal.aborted) queueMicrotask(cancelled)
      })

      requests_per_user.set(user, [...get_list_for_user(user), {challenge, raw}])
      notify(user)

      const assertion = await authorization
      if (assertion === null) throw status(403)
      return assertion
    },
    {
      // Keep the exact bytes next to the parsed body
      parse: async ({request}) => {
        const raw = await request.text()
        try {
          return {raw, json: JSON.parse(raw)}
        } catch {
          return {raw, json: null}
        }
      },
      body: t.Object({raw: t.String({maxLength: 65536}), json: RequestBody})
    }
  )

  .use(middleware)

  // CSRF : answers only from our own page. Browsers always send Origin on POST.
  .onBeforeHandle(({request, status}) => {
    const origin = request.headers.get('origin')
    if (request.method === 'POST' && origin !== null && !same_host(origin, request.url)) {
      console.warn(`Cross-site answer from ${origin}`)
      return status(403)
    }
  })

  /// Long-poll: answers right away if `known` (comma-separated challenges) is outdated, else on the next change
  .get(
    '/list',
    ({user, query: {known}, request}): Promise<PendingRequest[]> | PendingRequest[] => {
      const current = get_list_for_user(user)
      if (known !== current.map(r => r.challenge).join(',')) return current
      return new Promise(done => {
        const drop = () => {
          clearTimeout(to)
          const left = (user_waiting.get(user) ?? []).filter(w => w !== waiter)
          if (left.length === 0) user_waiting.delete(user)
          else user_waiting.set(user, left)
        }
        const waiter = (list: PendingRequest[]) => {
          clearTimeout(to)
          done(list)
        }
        const to = setTimeout(() => {
          drop()
          done(get_list_for_user(user))
        }, LIST_TIMEOUT)
        // Tab closed, page left : forget it now, and end the handler (nobody reads the answer)
        request.signal.addEventListener(
          'abort',
          () => {
            drop()
            done([])
          },
          {once: true}
        )
        user_waiting.set(user, [...(user_waiting.get(user) ?? []), waiter])
      })
    },
    {query: t.Object({known: t.String()})}
  )

  /// Authorize a challenge with the passkey's assertion (checked by the PAM client, not here)
  .post(
    '/authorize/:challenge',
    ({params: {challenge}, body, status, user}) => {
      if (!answer_callback(challenge, user, body)) return status(400)
    },
    {params: t.Object({challenge: t.String({format: 'uuid'})}), body: Assertion}
  )

  .post(
    '/block/:challenge',
    ({params: {challenge}, status, user}) => {
      if (!answer_callback(challenge, user, null)) return status(400)
    },
    {params: t.Object({challenge: t.String({format: 'uuid'})})}
  )
