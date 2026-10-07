import {mkdtempSync, writeFileSync} from 'fs'
import {tmpdir} from 'os'
import {join} from 'path'
import {expect, test} from 'vitest'

import {public_origin, served_module} from '@/helpers/module.server'

test('served module', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pam_web_'))
  expect(served_module(dir)).toBe(null)
  writeFileSync(join(dir, 'pam_web.version'), '0.4.0\n')
  // sha256sum's format
  writeFileSync(join(dir, 'pam_web.so.sha256'), `${'ab'.repeat(32)}  pam_web.so\n`)
  expect(served_module(dir)).toEqual({version: '0.4.0', sha256: 'ab'.repeat(32)})
})

test('public origin', () => {
  const behind_traefik = new Request('http://pam.example.com/', {headers: {'X-Forwarded-Proto': 'https'}})
  expect(public_origin(behind_traefik)).toBe('https://pam.example.com')
  expect(public_origin(new Request('http://localhost:5173/'))).toBe('http://localhost:5173')
})
