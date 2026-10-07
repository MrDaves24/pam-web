/// COSE algorithm ids (pubKeyCredParams), as named in the config file
const ALGORITHMS: Record<number, string> = {[-7]: 'es256', [-8]: 'ed25519'}

const to_base64 = (bytes: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(bytes)))

/// What the passkey signs to approve a request : SHA-256(raw body ‖ "\n" ‖ code ‖ "\nallow").
/// Same as pam/src/lib.rs `challenge`, which recomputes it from its own body and code.
export async function approval_challenge(raw: string, code: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${raw}\n${code}\nallow`))
}

/// Sign the approval of `raw` with a passkey of this site (the browser asks which one)
export async function sign_approval(raw: string, code: string) {
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: await approval_challenge(raw, code),
      userVerification: 'required',
      allowCredentials: [],
      timeout: 60_000
    }
  })) as PublicKeyCredential | null
  if (credential === null) throw new Error('No passkey used')

  const response = credential.response as AuthenticatorAssertionResponse
  return {
    authenticator_data: to_base64(response.authenticatorData),
    client_data_json: to_base64(response.clientDataJSON),
    signature: to_base64(response.signature)
  }
}

/// The config line for a passkey : `key <alg> <base64 SPKI> [name]`
export function key_line(algorithm: number, spki: ArrayBuffer, name: string): string {
  const alg = ALGORITHMS[algorithm]
  if (alg === undefined) throw new Error(`Unsupported algorithm ${algorithm}`)
  return `key ${alg} ${to_base64(spki)} ${name.replace(/\s+/g, ' ')}`.trim()
}

/// Create a passkey on this device, return its config line. Nothing is sent to the server : the
/// line is copied by hand into the machine's config (the trust anchor).
export async function register_passkey(user: string, name: string): Promise<string> {
  const label = name.trim() || 'pam_web'
  const credential = (await navigator.credentials.create({
    publicKey: {
      // id = this page's domain, which the PAM client will check
      rp: {name: 'pam_web'},
      // Same id for a user : registering again on a device replaces its passkey. Hashed : at most 64 bytes.
      user: {
        id: await crypto.subtle.digest('SHA-256', new TextEncoder().encode(user)),
        name: label,
        displayName: label
      },
      // No attestation to check, so no server challenge needed
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [
        {type: 'public-key', alg: -7},
        {type: 'public-key', alg: -8}
      ],
      authenticatorSelection: {residentKey: 'required', userVerification: 'required'},
      attestation: 'none'
    }
  })) as PublicKeyCredential | null
  if (credential === null) throw new Error('No passkey created')

  const response = credential.response as AuthenticatorAttestationResponse
  const spki = response.getPublicKey()
  if (spki === null) throw new Error("The browser didn't give the public key")
  return key_line(response.getPublicKeyAlgorithm(), spki, name)
}
