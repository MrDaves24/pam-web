import {readFileSync} from 'fs'

/// The PAM module the image serves at /pam_web.so (built by the Dockerfile), null when there's none (dev)
export function served_module(dir = 'build/client'): {version: string; sha256: string} | null {
  try {
    return {
      version: readFileSync(`${dir}/pam_web.version`, 'utf8').trim(),
      sha256: readFileSync(`${dir}/pam_web.so.sha256`, 'utf8').split(/\s/)[0]
    }
  } catch {
    return null
  }
}

/// This site as the browser sees it : Traefik terminates TLS and sets X-Forwarded-Proto (only it reaches us)
export function public_origin(request: Request): string {
  const url = new URL(request.url)
  return `${request.headers.get('x-forwarded-proto') ?? url.protocol.replace(':', '')}://${url.host}`
}
