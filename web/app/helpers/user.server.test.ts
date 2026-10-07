import {expect, test} from 'vitest'

import {check_request_token, DEV_USER, request_token, user_from_headers} from '@/helpers/user.server'

test('user from Authelia', () => {
  const headers = new Headers({'Remote-User': 'alice'})
  expect(user_from_headers(headers, false)).toBe('alice')
  expect(user_from_headers(new Headers(), false)).toBe(null)
  expect(user_from_headers(new Headers({'Remote-User': ''}), false)).toBe(null)
  // Dev : no Authelia, everyone is the dev user
  expect(user_from_headers(new Headers(), true)).toBe(DEV_USER)
})

test('request tokens', () => {
  const token = request_token('alice')
  expect(token).toMatch(/^[0-9a-f]{64}$/)
  expect(request_token('alice')).toBe(token)
  expect(request_token('other')).not.toBe(token)
  // Dev key "dev" : same as scripts/e2e.sh (printf dev | openssl dgst -sha256 -hmac dev)
  expect(request_token(DEV_USER)).toBe('7a7bd60797bcd90fc794b0a6e6fc36c6a78511f79ed4dd9246b9259f7c0c404e')

  expect(check_request_token('alice', token)).toBe(true)
  expect(check_request_token('other', token)).toBe(false)
  expect(check_request_token('alice', token.slice(1))).toBe(false)
  expect(check_request_token('alice', '')).toBe(false)
})
