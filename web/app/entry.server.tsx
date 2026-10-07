import {PassThrough} from 'node:stream'
import React from 'react'
import type {EntryContext} from 'react-router'
import {createReadableStreamFromReadable} from '@react-router/node'
import {ServerRouter} from 'react-router'
import {isbot} from 'isbot'
import type {RenderToPipeableStreamOptions} from 'react-dom/server'
import {renderToPipeableStream} from 'react-dom/server'

export const streamTimeout = 5_000

main().then()

async function main() {
  // Debug logs only in dev, or with LOG_LEVEL=debug
  if (import.meta.env.PROD && process.env['LOG_LEVEL']?.toLowerCase() !== 'debug') console.debug = () => {}

  if (import.meta.env.PROD) {
    let stopped = false
    const stop = async () => {
      if (stopped) {
        console.warn('Double stop caught')
        return
      }
      stopped = true

      console.info('CTRL+C caught, stopping server gracefully')

      console.info('Bye!')
      process.exit()
    }
    process.on('beforeExit', stop)
    process.on('SIGINT', stop)
    process.on('SIGHUP', stop)
    process.on('SIGTERM', stop)
  }

  console.info('Server started')
}

export default function handleRequest(
  request: Request,
  responseStatusCode: number,
  responseHeaders: Headers,
  routerContext: EntryContext
) {
  return new Promise((resolve, reject) => {
    let shellRendered = false
    const userAgent = request.headers.get('user-agent')

    // Ensure requests from bots and SPA Mode renders wait for all content to load before responding
    // https://react.dev/reference/react-dom/server/renderToPipeableStream#waiting-for-all-content-to-load-for-crawlers-and-static-generation
    const readyOption: keyof RenderToPipeableStreamOptions =
      (userAgent && isbot(userAgent)) || routerContext.isSpaMode ? 'onAllReady' : 'onShellReady'

    // Abort the rendering stream after the `streamTimeout` so it has time to
    // flush down the rejected boundaries
    let timeoutId: ReturnType<typeof setTimeout> | undefined = setTimeout(() => abort(), streamTimeout + 1000)

    const {pipe, abort} = renderToPipeableStream(<ServerRouter context={routerContext} url={request.url} />, {
      [readyOption]() {
        shellRendered = true
        const body = new PassThrough({
          final(callback: () => void) {
            // Clear the timeout to prevent retaining the closure and memory leak
            clearTimeout(timeoutId)
            timeoutId = undefined
            callback()
          }
        })
        const stream = createReadableStreamFromReadable(body)

        responseHeaders.set('Content-Type', 'text/html')

        pipe(body)

        resolve(
          new Response(stream, {
            headers: responseHeaders,
            status: responseStatusCode
          })
        )
      },
      onShellError(error: unknown) {
        reject(error)
      },
      onError(error: unknown) {
        responseStatusCode = 500
        // Log streaming rendering errors from inside the shell.  Don't log
        // errors encountered during initial shell rendering since they'll
        // reject and get logged in handleDocumentRequest.
        if (shellRendered) console.error(error)
      }
    })
  })
}
