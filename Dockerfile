# Checks (typecheck, lint, tests) aren't run here.

# The PAM module, served at /pam_web.so. It needs glibc 2.34 : Debian 12, Ubuntu 22.04, RHEL 9 and later.
# Built for the architecture of the machine building the image.
FROM rust:1-slim-bookworm AS pam
RUN apt-get update -qq && apt-get install -qq -y libpam0g-dev > /dev/null
WORKDIR /pam
COPY pam/ ./
RUN cargo build --release --locked && mkdir /out && cp target/release/libpam.so /out/pam_web.so \
  && cd /out && sha256sum pam_web.so > pam_web.so.sha256 \
  && sed -n 's/^version = "\(.*\)"/\1/p' /pam/Cargo.toml | head -1 > pam_web.version

FROM node:26-alpine AS build
WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build && npm prune --omit=dev

FROM node:26-alpine
# PID 1 that forwards signals : node alone ignores SIGTERM as PID 1 (docker stop would wait 10 s, then kill)
RUN apk add --no-cache tini
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/build ./build
COPY --from=pam /out/ ./build/client/

USER node
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node_modules/.bin/react-router-serve", "build/server/index.js"]
HEALTHCHECK --interval=30s --timeout=15s --start-period=10s --retries=3 CMD wget -qO /dev/null http://localhost:3000/api/health || exit 1
