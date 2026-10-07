import React, {useEffect, useState} from 'react'
import {data as response, useLoaderData, type LoaderFunctionArgs} from 'react-router'

import api from '@/api/client.client'
import {get_list_for_user, type PendingRequest, type RequestContext} from '@/api/endpoints/authorization'
import {register_passkey, sign_approval} from '@/helpers/passkey'
import {public_origin, served_module} from '@/helpers/module.server'
import {request_token, user_from_headers} from '@/helpers/user.server'

export async function loader({request}: LoaderFunctionArgs): Promise<{
  user: string
  token: string
  list: PendingRequest[]
  module: {version: string; sha256: string} | null
  origin: string
}> {
  console.debug('loader')

  // Authelia redirects to its login before we get here : no user = not behind Authelia
  const user = user_from_headers(request.headers)
  if (user === null) throw response('Not logged in (is Authelia in front?)', {status: 401})

  console.info(`User ${user} connected`)

  return {
    user,
    token: request_token(user),
    list: get_list_for_user(user),
    module: served_module(),
    origin: public_origin(request)
  }
}

export default function Page() {
  const data = useLoaderData<typeof loader>()
  const [requests, setRequests] = useState(data.list)
  // Stopped on unmount (also : StrictMode mounts twice in dev, one loop is left)
  useEffect(() => {
    const stop = new AbortController()
    long_poll(stop.signal).then()
    return () => stop.abort()
  }, [])

  const long_poll = async (signal: AbortSignal) => {
    let known = data.list.map(r => r.challenge)
    while (!signal.aborted) {
      console.debug('Long poll')
      const res = await api.authorization.list.get({query: {known: known.join(',')}, fetch: {signal}}).catch(() => null)
      console.debug('Long poll answered')
      if (signal.aborted) return
      // Session expired : Authelia redirects (or 401), reloading shows its login
      if (res?.response.status === 401 || res?.response.type === 'opaqueredirect') {
        window.location.reload()
        return
      }
      if (!res?.response.ok || !res.data) {
        await new Promise(r => setTimeout(r, 5000))
        continue
      }

      // The server sends the full list, removals included
      setRequests(res.data)
      known = res.data.map(r => r.challenge)
    }
  }

  const answered = (challenge: string) => setRequests(list => list.filter(r => r.challenge !== challenge))

  return (
    <>
      <header className='flex items-baseline justify-between gap-4'>
        <div>
          <h1 className='text-2xl font-semibold tracking-tight'>pam_web</h1>
          <p className='text-muted text-sm'>Approve sudo from your browser</p>
        </div>
        <div className='text-muted text-sm'>{data.user}</div>
      </header>

      <section className='mt-10'>
        <h2 className='text-muted mb-3 text-xs font-medium tracking-widest uppercase'>Requests</h2>
        {requests.length === 0 ? (
          <p className='border-line text-muted rounded-xl border border-dashed px-5 py-8 text-center text-sm'>
            Nothing waiting. Run <code className='font-mono'>sudo</code> on a machine, it shows up here.
          </p>
        ) : (
          <ul className='space-y-4'>
            {requests.map(request => (
              <RequestCard key={request.challenge} request={request} answered={answered} />
            ))}
          </ul>
        )}
      </section>

      <Setup data={data} />
    </>
  )
}

// eslint-disable-next-line no-unused-vars
function RequestCard({request, answered}: {request: PendingRequest; answered: (challenge: string) => void}) {
  // Shown from the exact bytes that get signed
  const r = JSON.parse(request.raw) as RequestContext
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState<'passkey' | 'sending' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const code = r.code ?? typed
  const challenge = request.challenge

  const authorize = async () => {
    setError(null)
    setBusy('passkey')
    let assertion
    try {
      assertion = await sign_approval(request.raw, code)
    } catch (e) {
      console.warn('Passkey signature failed', e)
      setError(`The passkey didn't sign: ${e instanceof Error ? e.message : e}`)
      setBusy(null)
      return
    }
    setBusy('sending')
    const res = await api.authorization.authorize({challenge}).post(assertion)
    setBusy(null)
    if (res.response.ok) answered(challenge)
    else setError('The server lost this request (timed out?)')
  }

  const refuse = async () => {
    setError(null)
    setBusy('sending')
    const res = await api.authorization.block({challenge}).post()
    setBusy(null)
    if (res.response.ok) answered(challenge)
    else setError('The server lost this request (timed out?)')
  }

  const who = r.ruser && r.ruser !== r.pam_user ? `${r.pam_user}, asked by ${r.ruser}` : r.pam_user
  return (
    <li className='bg-card border-line rounded-xl border p-5 shadow-sm'>
      {/* Context first, then the code : read what you approve */}
      <div className='flex items-baseline justify-between gap-3'>
        <p>
          <span className='font-medium'>{r.service ?? 'PAM'}</span> <span className='text-muted'>on</span>{' '}
          <span className='font-medium'>{r.hostname}</span>
        </p>
        <time className='text-muted shrink-0 text-xs'>{new Date(r.ts * 1000).toLocaleTimeString()}</time>
      </div>
      <pre className='bg-sunk mt-3 rounded-lg px-3 py-2 font-mono text-sm break-all whitespace-pre-wrap'>
        {r.cmdline.join(' ') || '(no command line)'}
      </pre>
      <p className='text-muted mt-2 text-sm'>
        as {who} (uid {r.uid}){r.tty && ` · ${r.tty}`}
        {r.rhost && ` · from ${r.rhost}`}
      </p>

      <div className='border-line mt-4 border-t pt-4'>
        {r.code === undefined ? (
          <label className='block'>
            <span className='text-muted text-sm'>Type the code shown in your terminal</span>
            <input
              className='border-line bg-bg focus:border-accent mt-1 block w-full rounded-lg border px-3 py-2 text-center font-mono text-2xl tracking-[0.4em] outline-none'
              inputMode='numeric'
              autoComplete='off'
              maxLength={6}
              placeholder='······'
              value={typed}
              onChange={e => setTyped(e.target.value.replace(/\D/g, ''))}
            />
          </label>
        ) : (
          <div className='flex items-baseline justify-between gap-3'>
            <span className='text-muted text-sm'>Same code as your terminal?</span>
            <span className='font-mono text-2xl tracking-widest'>
              {r.code.slice(0, 3)} {r.code.slice(3)}
            </span>
          </div>
        )}

        {error && <p className='text-danger mt-3 text-sm'>{error}</p>}

        <div className='mt-4 flex gap-3'>
          <button
            onClick={authorize}
            disabled={code.length !== 6 || busy !== null}
            className='bg-accent text-accent-fg flex-1 rounded-lg px-4 py-2 font-medium'
          >
            {busy === 'passkey' ? 'Waiting for your passkey…' : 'Authorize'}
          </button>
          <button
            onClick={refuse}
            disabled={busy !== null}
            className='border-line text-muted hover:text-fg rounded-lg border px-4 py-2'
          >
            Refuse
          </button>
        </div>
      </div>
    </li>
  )
}

function CopyButton({text}: {text: string}) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      className='text-muted hover:text-fg shrink-0 text-xs'
      onClick={async () => {
        await navigator.clipboard.writeText(text)
        setCopied(true)
        setTimeout(() => setCopied(false), 1500)
      }}
    >
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}

/// A copyable block of text
function Block({text}: {text: string}) {
  return (
    <div className='bg-sunk mt-2 flex items-start gap-3 rounded-lg px-3 py-2'>
      <pre className='flex-1 font-mono text-xs break-all whitespace-pre-wrap'>{text}</pre>
      <CopyButton text={text} />
    </div>
  )
}

function Step({n, title, children}: {n: number; title: string; children: React.ReactNode}) {
  return (
    <li className='flex gap-4'>
      <span className='border-line text-muted flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-xs'>
        {n}
      </span>
      <div className='min-w-0 flex-1 text-sm'>
        <h3 className='font-medium'>{title}</h3>
        {children}
      </div>
    </li>
  )
}

/// Registered key lines, kept in this browser only (the server stores nothing, password managers don't show them)
function useKeyLines(user: string) {
  const storage = `pam_web:keys:${user}`
  const [lines, setLines] = useState<string[]>([])
  useEffect(() => {
    try {
      setLines(JSON.parse(localStorage.getItem(storage) ?? '[]'))
    } catch {
      setLines([])
    }
  }, [storage])
  const save = (next: string[]) => {
    setLines(next)
    try {
      localStorage.setItem(storage, JSON.stringify(next))
    } catch {
      // Private mode, storage blocked : kept until the page closes
    }
  }
  return [lines, save] as const
}

function Setup({data}: {data: Awaited<ReturnType<typeof loader>>}) {
  const [name, setName] = useState('')
  const [registering, setRegistering] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [keys, setKeys] = useKeyLines(data.user)

  const register = async () => {
    setError(null)
    setRegistering(true)
    try {
      setKeys([...keys, await register_passkey(data.user, name)])
      setName('')
    } catch (e) {
      console.warn('Passkey registration failed', e)
      setError(`No passkey created: ${e instanceof Error ? e.message : e}`)
    }
    setRegistering(false)
  }

  const config = [`user ${data.user} ${data.token}`, ...keys].join('\n')
  return (
    <details className='group mt-12'>
      <summary className='text-muted hover:text-fg cursor-pointer text-xs font-medium tracking-widest uppercase'>
        Set up a machine
      </summary>
      <ol className='mt-5 space-y-6'>
        <Step n={1} title='Install the PAM module'>
          {data.module === null ? (
            <p className='text-muted mt-1'>
              This build doesn&apos;t serve it: build it with <code className='font-mono'>cargo build --release</code>{' '}
              in <code className='font-mono'>pam/</code>.
            </p>
          ) : (
            <>
              <p className='text-muted mt-1'>
                <a href='/pam_web.so' download>
                  pam_web.so
                </a>{' '}
                v{data.module.version}. It runs as root: before installing, check that{' '}
                <code className='font-mono'>sha256sum pam_web.so</code> matches.
              </p>
              <Block text={data.module.sha256} />
            </>
          )}
        </Step>

        <Step n={2} title='Register passkeys'>
          <p className='text-muted mt-1'>
            One per device allowed to approve (this laptop, a backup key, …). Registering again on the same device
            replaces its passkey.
          </p>
          <div className='mt-2 flex gap-2'>
            <input
              className='border-line bg-card focus:border-accent min-w-0 flex-1 rounded-lg border px-3 py-1.5 outline-none'
              placeholder='Name, e.g. MacBook Touch ID'
              value={name}
              onChange={e => setName(e.target.value)}
            />
            <button
              onClick={register}
              disabled={registering}
              className='bg-accent text-accent-fg rounded-lg px-3 py-1.5 font-medium'
            >
              {registering ? 'Waiting…' : 'Register'}
            </button>
          </div>
          {error && <p className='text-danger mt-2'>{error}</p>}
          {keys.length > 0 && (
            <ul className='mt-3 space-y-1'>
              {keys.map((line, i) => (
                <li key={line} className='flex items-center gap-3'>
                  <span className='flex-1 truncate'>{line.split(' ').slice(3).join(' ') || `key ${i + 1}`}</span>
                  <button
                    className='text-muted hover:text-danger text-xs'
                    onClick={() => setKeys(keys.filter(k => k !== line))}
                  >
                    Forget
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Step>

        <Step n={3} title='Write the config'>
          <p className='text-muted mt-1'>
            <code className='font-mono'>/etc/pam_web/&lt;unix user&gt;</code>, root:root, mode 0600. The file name is
            the account being authenticated: you for sudo, <code className='font-mono'>root</code> for su.
          </p>
          <Block text={config} />
        </Step>

        <Step n={4} title='Enable it'>
          <p className='text-muted mt-1'>
            In <code className='font-mono'>/etc/pam.d/sudo</code>, before the password line. Keep a root shell open
            while you try it.
          </p>
          <Block text={`auth sufficient pam_web.so ${data.origin}/api/authorization/request`} />
        </Step>
      </ol>
    </details>
  )
}
