import {createHmac, timingSafeEqual} from 'crypto'
import {readFileSync} from 'fs'
import {env} from 'process'

/// In dev, everyone is this user (no Authelia in front)
export const DEV_USER = 'dev'

/// The Authelia user : its forward auth sets `Remote-User`, and Traefik drops it from outside requests.
/// Null if missing (only possible if pam isn't behind Authelia).
export function user_from_headers(headers: Headers, dev = import.meta.env.DEV): string | null {
  if (dev) return DEV_USER
  return headers.get('remote-user') || null
}

/// Signs the users' request tokens (a docker secret, at least 32 random bytes). Read at startup : missing = crash.
function read_key(dev = import.meta.env.DEV): Buffer {
  if (dev) return Buffer.from('dev')
  const key = readFileSync(env.TOKEN_KEY_FILE ?? '/run/secrets/pam_token_key')
  if (key.length < 32) throw new Error('The token key must be at least 32 bytes')
  return key
}
const KEY = read_key()

/// What a PAM client must send to create requests for `user` (shown on the page, in the config's `user` line)
export function request_token(user: string): string {
  return createHmac('sha256', KEY).update(user).digest('hex')
}

export function check_request_token(user: string, token: string): boolean {
  const expected = Buffer.from(request_token(user))
  const given = Buffer.from(token)
  return given.length === expected.length && timingSafeEqual(given, expected)
}
