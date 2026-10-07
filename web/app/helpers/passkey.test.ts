import {expect, test} from 'vitest'

import {approval_challenge, key_line} from '@/helpers/passkey'

// Same key as pam/src/lib.rs tests (openssl genpkey, P-256)
const P256 =
  'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEODH6vwvuPAOqvQ+mvX9eOvEEr2z/Df9jgLNSEMMVaLnqcQsrtZvAeZ6TAmek+ZYcEb1M06y2ZaCxxgH7lP8PWg=='
const spki = Uint8Array.from(atob(P256), c => c.charCodeAt(0)).buffer

test('key line', () => {
  expect(key_line(-7, spki, 'MacBook  Touch ID')).toBe(`key es256 ${P256} MacBook Touch ID`)
  expect(key_line(-7, spki, '')).toBe(`key es256 ${P256}`)
  expect(key_line(-8, spki, 'x')).toBe(`key ed25519 ${P256} x`)
  expect(() => key_line(-257, spki, 'x')).toThrow()
})

test('approval challenge', async () => {
  // Same vector as pam/src/lib.rs tests
  const challenge = Buffer.from(await approval_challenge('{"a":1}', '123456')).toString('base64url')
  expect(challenge).toBe('rzaEcLei7fhZ2JYuPdC_4qUdhHzwadv6vuTPYcXcsTE')
})
