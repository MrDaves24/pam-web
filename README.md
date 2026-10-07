# pam_web
Approve `sudo` (or any PAM authentication) from your browser instead of typing a password.

This project assumes it is protected by SSO, asking the user to log in, then forwarding headers to identify the user. Authelia is a good example for this case.

- **client** (`pam/`): the PAM module, `pam_web.so`. It runs inside sudo/su, shows a 6-digit code in the terminal and asks the server.
- **server** (`web/`): the website, in docker. It relays requests to your browser and keeps nothing on disk.
- **browser**: where you approve, after checking the context (host, user, service, tty, command) and that the code matches your terminal. Sometimes (1 in 3) the code isn't sent: you type it from the terminal.

Approving signs the request with a passkey (Touch ID, YubiKey, a password manager). The client checks that signature against the `key` lines of its config: the server only relays, and can't approve anything by itself. It can still block or delay requests.

## New machine
Once per user, not per machine:
1. Log into `pam.example.com` (through Authelia), open "Set up a machine", name the device and click "Register" (Touch ID, YubiKey, a password manager...). Its `key es256 <base64> <name>` line joins the config shown in step 3. The server stores nothing: the lines are only kept in this browser, so copy them somewhere safe too. Register a backup key the same way.

On each machine, as root:
1. Install the client: download `pam_web.so` from the page ("Set up a machine"), built with the docker image, and check it against the hash the page shows (it runs as root). Or build it yourself: `cd pam && cargo build --release`, it's `target/release/libpam.so`. Then into the PAM module dir (`/lib/security/`, or `/usr/lib/<arch>-linux-gnu/security/` on Debian), root `0644`.
2. Write `/etc/pam_web/<unix user>`, root:root `0600` (the page shows the whole file, with a Copy button):
   ```
   user authelia_username 3f9a6c0e5b...c1
   key es256 MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE... device1
   key es256 MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE... device2
   ```
   - `user` = your web (Authelia) user, who approves, and its request token: only machines with it can create requests for you. Keep it secret, hence `0600`.
   - The file name is the account being authenticated (`PAM_USER`): for `sudo` it's you, for `su` it's the target, so `/etc/pam_web/root` decides who can approve `su`.
   - No file = pam_web is ignored for that user. A file that isn't root-owned `0600`, without a `key` line, or with an invalid line, fails the authentication.
   - The passkeys belong to the site in the pam.d URL (`pam.example.com`): a passkey registered elsewhere (e.g. `localhost`) doesn't work.
3. **Keep a root shell open** (`sudo -s` in another terminal) before touching pam.d, in case you lock yourself out.
4. Add to `/etc/pam.d/sudo` (and others if wanted), before the password line:
   ```
   auth sufficient pam_web.so https://pam.example.com/api/authorization/request
   ```
   `sufficient`: if pam_web fails (blocked, timeout, server down), the password still works. An optional second argument sets the log level (`debug`, `trace`, ...). Logs go to syslog (`LOG_AUTHPRIV`).
5. Test: `sudo -k && sudo true` and approve (once with the code shown, once typed: it's random, 1 in 3), then again and refuse: the password prompt should appear.

Revoke a passkey: delete its `key` line. Remove a machine: remove the pam.d line.

## Development
- Client: `cd pam && cargo test`. `--features debug` logs to the terminal instead of syslog.
- Server: `cd web && npm i && npm run dev` (in dev there's no Authelia: everyone is the user `dev`), `npm run check`, `npm test`.
- End-to-end: `scripts/e2e.sh` runs the real `pam_web.so` through libpam (pamtester) against the dev server. Its header has the commands to run it locally.
- Browser end-to-end: `scripts/e2e-browser.sh` drives the page in headless Chrome (Playwright, a virtual authenticator) and the real `pam_web.so`: passkey registration, approvals, typed codes, refusals, cancelled sudo. Same: commands in its header.
- Production build: `cd web && npm run build && node e2e/prod.mjs` checks it has no dev shortcut (dev user, dev token key).

## Deployment
The server runs behind Traefik and Authelia's forward auth, and trusts the `Remote-User` header: only Traefik may reach it, and Traefik must drop `Remote-User` from incoming requests.
- The page and `/api/*` go through Authelia, except `/api/authorization/request` (the PAM clients have no session): a second Traefik router on that path, without the middleware.
- The request tokens are HMACs of the user name with a secret key: a file of at least 32 random bytes (`head -c 32 /dev/urandom`), mounted as a docker secret at `/run/secrets/pam_token_key` (or `TOKEN_KEY_FILE`), readable by uid 1000 (the container runs as `node`). The server doesn't start without it. Changing it changes every token: update the machines' `user` lines.

Example `docker-compose.yml`, building the image from this repository (Traefik and Authelia already running, on the `proxy` network, with an `authelia` middleware):
```yaml
services:
  pam:
    build: https://github.com/MrDaves24/pam-web.git#main
    restart: unless-stopped
    # environment:
    #   LOG_LEVEL: debug
    secrets: [pam_token_key]
    networks: [proxy]
    labels:
      traefik.enable: true
      traefik.http.services.pam.loadbalancer.server.port: 3000
      # The page and the API, behind Authelia
      traefik.http.routers.pam.rule: Host(`pam.example.com`)
      traefik.http.routers.pam.middlewares: authelia@docker
      # The PAM clients' endpoint, without Authelia (they authenticate with their request token)
      traefik.http.routers.pam-request.rule: Host(`pam.example.com`) && Path(`/api/authorization/request`)

secrets:
  pam_token_key:
    file: ./pam_token_key # head -c 32 /dev/urandom > pam_token_key

networks:
  proxy:
    external: true
```
Update with `docker compose build --pull && docker compose up -d`.

The image also builds `pam_web.so` (served on the page) for its own architecture, needing glibc 2.34 (Debian 12, Ubuntu 22.04, RHEL 9 and later). Machines with another architecture: build it yourself (see above).

## License
[MIT with the Commons Clause](LICENSE): use, modify and share it freely, including inside your company, but don't sell it.
