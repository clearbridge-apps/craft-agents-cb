/**
 * Web UI HTTP handler and standalone server.
 *
 * The core logic lives in `createWebuiHandler()` which returns a web-standard
 * fetch handler `(Request) => Promise<Response>`. This handler can be:
 *
 * 1. **Embedded** — attached to the WsRpcServer's HTTPS server via the
 *    node-adapter so that HTTP and WSS share a single port.
 * 2. **Standalone** — wrapped in `Bun.serve()` via `startWebuiHttpServer()`
 *    for separate-port deployments or development.
 */

import { join, extname } from 'node:path'
import {
  RateLimiter,
  initPasswordHash,
  verifyPassword,
  createSessionToken,
  createUserSessionToken,
  validateSession,
  buildSessionCookie,
  buildLogoutCookie,
} from './auth'
import {
  generateAuthUrl,
  exchangeCodeForTokens,
  verifyIdToken,
  validateDomain,
  GoogleAuthFlowStore,
  type GoogleAuthConfig,
} from './google-auth'
import { generateCallbackPage } from '@craft-agent/shared/auth'
import { getDatabase, UserRepository } from '@craft-agent/shared/database'
import type { PlatformServices } from '../runtime/platform'

// ---------------------------------------------------------------------------
// MIME types for static file serving
// ---------------------------------------------------------------------------

const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.webp': 'image/webp',
  '.map': 'application/json',
}

function getMimeType(path: string): string {
  return MIME_TYPES[extname(path).toLowerCase()] ?? 'application/octet-stream'
}

function getForwardedValue(req: Request, key: 'proto' | 'host'): string | null {
  const forwarded = req.headers.get('forwarded')
  if (!forwarded) return null

  const match = forwarded.match(new RegExp(`${key}="?([^;,"]+)"?`, 'i'))
  return match?.[1]?.trim() || null
}

function getRequestProto(req: Request): string {
  return req.headers.get('x-forwarded-proto')?.split(',')[0]?.trim()
    || getForwardedValue(req, 'proto')
    || new URL(req.url).protocol.replace(/:$/, '')
}

function getRequestHost(req: Request): string | null {
  return req.headers.get('x-forwarded-host')?.split(',')[0]?.trim()
    || getForwardedValue(req, 'host')
    || req.headers.get('host')
}

function formatHostWithPort(host: string, port: number): string {
  try {
    const parsed = new URL(`http://${host}`)
    const hostname = parsed.hostname.includes(':') ? `[${parsed.hostname}]` : parsed.hostname
    return `${hostname}:${port}`
  } catch {
    const withoutPort = host.replace(/:\d+$/, '')
    return `${withoutPort}:${port}`
  }
}

export function shouldUseSecureCookies(req: Request, secureCookies?: boolean): boolean {
  if (secureCookies != null) return secureCookies
  return getRequestProto(req) === 'https'
}

export interface ResolveWebSocketUrlOptions {
  publicWsUrl?: string
  wsProtocol: 'ws' | 'wss'
  wsPort: number
}

export function resolveWebSocketUrl(
  req: Request,
  { publicWsUrl, wsProtocol, wsPort }: ResolveWebSocketUrlOptions,
): string {
  if (publicWsUrl) return publicWsUrl

  const host = getRequestHost(req)
  if (host) {
    return `${wsProtocol}://${formatHostWithPort(host, wsPort)}`
  }

  return `${wsProtocol}://127.0.0.1:${wsPort}`
}

// ---------------------------------------------------------------------------
// Handler options (shared between embedded and standalone modes)
// ---------------------------------------------------------------------------

/** Dependencies for the /api/oauth/callback HTTP route (server-side OAuth completion). */
export interface OAuthCallbackDeps {
  flowStore: { getByState: (state: string) => any; remove: (state: string) => void }
  credManager: { exchangeAndStore: (...args: any[]) => Promise<any> }
  sessionManager: { completeAuthRequest: (...args: any[]) => Promise<void> }
  pushSourcesChanged: (workspaceId: string) => void
}

export interface WebuiHandlerOptions {
  /** Path to built web UI dist/ directory. */
  webuiDir: string
  /** Secret used to sign JWTs — typically CRAFT_SERVER_TOKEN. */
  secret: string
  /** Optional separate web UI password. Falls back to `secret` for verification. */
  password?: string
  /** Explicit Secure-cookie override. When unset, infer from the request / proxy headers. */
  secureCookies?: boolean
  /** Optional browser-facing WebSocket URL override for reverse-proxy deployments. */
  publicWsUrl?: string
  /** RPC WebSocket protocol used when building a browser-facing fallback URL. */
  wsProtocol: 'ws' | 'wss'
  /** RPC WebSocket port used when building a browser-facing fallback URL. */
  wsPort: number
  /** Health check function (injected from existing server handler). */
  getHealthCheck: () => { status: string }
  /** Logger. */
  logger: PlatformServices['logger']
  /** OAuth callback deps — when provided, enables /api/oauth/callback route. */
  oauthCallbackDeps?: OAuthCallbackDeps
  /**
   * Trusted proxy IPs/CIDRs. When set, proxy headers (x-forwarded-for, x-forwarded-proto)
   * are only trusted from these sources. When empty/unset, proxy headers are ignored
   * and 'direct' is used as the rate-limit key.
   */
  trustedProxies?: string[]
  /** Google OAuth configuration. When provided, enables Google SSO routes. */
  googleAuthConfig?: GoogleAuthConfig
}

// ---------------------------------------------------------------------------
// Handler factory — the core request handler
// ---------------------------------------------------------------------------

export interface WebuiHandler {
  /** Web-standard fetch handler. */
  fetch: (req: Request) => Promise<Response>
  /** Call on shutdown to release timers. */
  dispose: () => void
  /** Inject OAuth callback deps after bootstrap (lazy wiring). */
  setOAuthCallbackDeps: (deps: OAuthCallbackDeps) => void
}

/**
 * Create a web-standard fetch handler for the WebUI.
 *
 * This handler can be used directly with `Bun.serve({ fetch })`,
 * or adapted for Node's HTTP server via `nodeHttpAdapter()`.
 */
export function createWebuiHandler(options: WebuiHandlerOptions): WebuiHandler {
  const {
    webuiDir,
    secret,
    password,
    secureCookies,
    publicWsUrl,
    wsProtocol,
    wsPort,
    getHealthCheck,
    logger,
    trustedProxies,
    googleAuthConfig,
  } = options

  const rateLimiter = new RateLimiter(5, 60_000)
  const cleanupTimer = setInterval(() => rateLimiter.cleanup(), 120_000)

  const loginPassword = password || secret
  const trustedProxySet = new Set(trustedProxies ?? [])

  // Hash the login password at startup (async, but resolves before first auth attempt in practice)
  const passwordReady = initPasswordHash(loginPassword)

  // Google OAuth flow store (for PKCE code_verifier → state mapping)
  const googleFlowStore = new GoogleAuthFlowStore()

  // Database access for user management
  let userRepo: UserRepository | null = null
  function getUserRepo(): UserRepository {
    if (!userRepo) {
      userRepo = new UserRepository(getDatabase())
    }
    return userRepo
  }

  /** Extract client IP — only trusts proxy headers when trustedProxies is configured. */
  function getClientIp(req: Request): string {
    if (trustedProxySet.size > 0) {
      return req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
        ?? req.headers.get('x-real-ip')
        ?? 'direct'
    }
    return 'direct'
  }

  /** Build the absolute server URL from the incoming request. */
  function getServerUrl(req: Request): string {
    const proto = getRequestProto(req)
    const host = getRequestHost(req) ?? '127.0.0.1'
    return `${proto}://${host}`
  }

  async function fetch(req: Request): Promise<Response> {
    const url = new URL(req.url)
    const path = url.pathname
    const useSecureCookies = shouldUseSecureCookies(req, secureCookies)

    // ── Health endpoint (no auth) ──
    if (path === '/health') {
      const health = getHealthCheck()
      return Response.json(health, {
        status: health.status === 'ok' ? 200 : 503,
      })
    }

    // ── Auth providers info (no auth) ──
    if (path === '/api/auth/providers' && req.method === 'GET') {
      return Response.json({
        google: !!googleAuthConfig,
        password: true,
      })
    }

    // ── Login page (no auth) ──
    if (path === '/login' || path === '/login/') {
      const loginFile = Bun.file(join(webuiDir, 'login.html'))
      if (await loginFile.exists()) {
        return new Response(loginFile, {
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        })
      }
      return new Response('Login page not found', { status: 404 })
    }

    // ── Static assets that login page needs (no auth) ──
    if (path === '/favicon.ico' || path.startsWith('/login-assets/')) {
      const file = Bun.file(join(webuiDir, path))
      if (await file.exists()) {
        return new Response(file, {
          headers: { 'Content-Type': getMimeType(path) },
        })
      }
      return new Response('Not Found', { status: 404 })
    }

    // ── Google OAuth: initiate ──
    if (path === '/api/auth/google' && req.method === 'GET') {
      if (!googleAuthConfig) {
        return Response.json({ error: 'Google OAuth not configured' }, { status: 404 })
      }

      const config: GoogleAuthConfig = {
        ...googleAuthConfig,
        redirectUri: `${getServerUrl(req)}/api/auth/google/callback`,
      }

      try {
        const { url: authUrl, state, codeVerifier } = await generateAuthUrl(config)
        googleFlowStore.store(state, codeVerifier)
        return Response.redirect(authUrl, 302)
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Failed to generate auth URL'
        logger.error(`[webui] Google auth URL generation failed: ${msg}`)
        return Response.json({ error: 'Failed to initiate Google authentication' }, { status: 500 })
      }
    }

    // ── Google OAuth: callback ──
    if (path === '/api/auth/google/callback' && req.method === 'GET') {
      if (!googleAuthConfig) {
        return Response.json({ error: 'Google OAuth not configured' }, { status: 404 })
      }

      const code = url.searchParams.get('code')
      const state = url.searchParams.get('state')
      const error = url.searchParams.get('error')
      const errorDescription = url.searchParams.get('error_description')

      if (error) {
        const errorMsg = errorDescription || error
        logger.warn(`[webui] Google OAuth callback error: ${errorMsg}`)
        return new Response(
          generateCallbackPage({ title: 'Sign-in Failed', isSuccess: false, errorDetail: errorMsg }),
          { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } },
        )
      }

      if (!code || !state) {
        return new Response(
          generateCallbackPage({ title: 'Sign-in Failed', isSuccess: false, errorDetail: 'Missing code or state parameter' }),
          { status: 400, headers: { 'Content-Type': 'text/html; charset=utf-8' } },
        )
      }

      const flow = googleFlowStore.get(state)
      if (!flow) {
        return new Response(
          generateCallbackPage({ title: 'Sign-in Failed', isSuccess: false, errorDetail: 'OAuth flow expired or invalid state' }),
          { status: 400, headers: { 'Content-Type': 'text/html; charset=utf-8' } },
        )
      }
      googleFlowStore.remove(state)

      try {
        const config: GoogleAuthConfig = {
          ...googleAuthConfig,
          redirectUri: `${getServerUrl(req)}/api/auth/google/callback`,
        }

        const tokens = await exchangeCodeForTokens(config, code, flow.codeVerifier)
        const googleUser = await verifyIdToken(tokens.idToken, config.clientId)

        // Domain restriction check
        if (!validateDomain(googleUser.email, googleUser.hd, config.allowedDomain)) {
          logger.warn(`[webui] Google OAuth domain rejected: ${googleUser.email} (hd=${googleUser.hd})`)
          return new Response(
            generateCallbackPage({ title: 'Sign-in Failed', isSuccess: false, errorDetail: 'Your email domain is not authorized' }),
            { status: 403, headers: { 'Content-Type': 'text/html; charset=utf-8' } },
          )
        }

        const repo = getUserRepo()
        let user = repo.findByGoogleSub(googleUser.sub)

        if (user) {
          // Existing user — update last login
          if (!user.isActive) {
            logger.warn(`[webui] Deactivated user attempted login: ${user.email}`)
            return new Response(
              generateCallbackPage({ title: 'Sign-in Failed', isSuccess: false, errorDetail: 'Account is deactivated' }),
              { status: 403, headers: { 'Content-Type': 'text/html; charset=utf-8' } },
            )
          }
          repo.updateLastLogin(user.id)
        } else {
          // New user — first user becomes admin, rest are regular users
          const isFirstUser = repo.listAll().length === 0
          user = repo.create({
            email: googleUser.email,
            name: googleUser.name,
            avatarUrl: googleUser.picture,
            googleSub: googleUser.sub,
            role: isFirstUser ? 'admin' : 'user',
            isActive: true,
          })
          logger.info(`[webui] Created new user: ${user.email} (role=${user.role})`)
        }

        const jwt = await createUserSessionToken(secret, user)
        logger.info(`[webui] Google OAuth login: ${user.email}`)

        return Response.redirect('/', 302, {
          'Set-Cookie': buildSessionCookie(jwt, useSecureCookies),
        })
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Google authentication failed'
        logger.error(`[webui] Google OAuth callback failed: ${msg}`)
        return new Response(
          generateCallbackPage({ title: 'Sign-in Failed', isSuccess: false, errorDetail: msg }),
          { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } },
        )
      }
    }

    // ── Password login endpoint (fallback) ──
    if (path === '/api/auth' && req.method === 'POST') {
      await passwordReady
      const ip = getClientIp(req)

      if (!rateLimiter.check(ip)) {
        logger.warn(`[webui] Rate limited auth attempt from ${ip}`)
        return Response.json(
          { error: 'Too many attempts. Try again later.' },
          { status: 429 },
        )
      }

      let body: { password?: string }
      try {
        body = await req.json() as { password?: string }
      } catch {
        return Response.json({ error: 'Invalid request body' }, { status: 400 })
      }

      if (!body.password || typeof body.password !== 'string') {
        return Response.json({ error: 'Password is required' }, { status: 400 })
      }

      if (!await verifyPassword(body.password)) {
        logger.warn(`[webui] Failed auth attempt from ${ip}`)
        return Response.json({ error: 'Invalid credentials' }, { status: 401 })
      }

      const jwt = await createSessionToken(secret)
      logger.info(`[webui] Successful password auth from ${ip}`)

      return Response.json({ ok: true }, {
        status: 200,
        headers: {
          'Set-Cookie': buildSessionCookie(jwt, useSecureCookies),
        },
      })
    }

    // ── Logout endpoint ──
    if (path === '/api/auth/logout' && req.method === 'POST') {
      return new Response(null, {
        status: 204,
        headers: {
          'Set-Cookie': buildLogoutCookie(useSecureCookies),
        },
      })
    }

    // ── OAuth callback (no cookie auth — state param is CSRF protection) ──
    // Receives redirect from the relay (or directly from OAuth provider for MCP sources).
    // Completes the token exchange server-side and renders a success/error page.
    if (path === '/api/oauth/callback' && req.method === 'GET' && options.oauthCallbackDeps) {
      const code = url.searchParams.get('code')
      const state = url.searchParams.get('state')
      const error = url.searchParams.get('error')
      const errorDescription = url.searchParams.get('error_description')

      if (error) {
        const flow = state ? options.oauthCallbackDeps.flowStore.getByState(state) : null
        if (flow && state) options.oauthCallbackDeps.flowStore.remove(state)
        const errorMsg = errorDescription || error
        logger.warn(`[webui] OAuth callback error: ${errorMsg}`)
        return new Response(generateCallbackPage({ title: 'Authorization Failed', isSuccess: false, errorDetail: errorMsg }), {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        })
      }

      if (!code || !state) {
        return new Response(generateCallbackPage({ title: 'Authorization Failed', isSuccess: false, errorDetail: 'Missing code or state parameter' }), {
          status: 400,
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        })
      }

      try {
        const { completeOAuthFlow } = await import('../handlers/rpc/oauth')
        const result = await completeOAuthFlow({
          code,
          state,
          flowStore: options.oauthCallbackDeps.flowStore,
          credManager: options.oauthCallbackDeps.credManager as any,
          sessionManager: options.oauthCallbackDeps.sessionManager,
          pushSourcesChanged: options.oauthCallbackDeps.pushSourcesChanged,
          logger,
          // No clientId/workspaceId — HTTP callback skips ownership checks (state is auth)
        })

        if (result.success) {
          return new Response(generateCallbackPage({ title: 'Authorization Successful', isSuccess: true }), {
            status: 200,
            headers: { 'Content-Type': 'text/html; charset=utf-8' },
          })
        } else {
          return new Response(generateCallbackPage({ title: 'Authorization Failed', isSuccess: false, errorDetail: result.error }), {
            status: 200,
            headers: { 'Content-Type': 'text/html; charset=utf-8' },
          })
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Token exchange failed'
        logger.error(`[webui] OAuth callback failed: ${msg}`)
        return new Response(generateCallbackPage({ title: 'Authorization Failed', isSuccess: false, errorDetail: msg }), {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        })
      }
    }

    // ── Current user endpoint ──
    if (path === '/api/auth/me' && req.method === 'GET') {
      const session = await validateSession(req.headers.get('cookie'), secret)
      if (!session) {
        return Response.json({ error: 'Unauthorized' }, { status: 401 })
      }

      const repo = getUserRepo()
      const user = repo.findById(session.userId)
      if (!user) {
        return Response.json({ error: 'User not found' }, { status: 404 })
      }

      return Response.json({
        id: user.id,
        email: user.email,
        name: user.name,
        avatarUrl: user.avatarUrl,
        role: user.role,
      })
    }

    // ── Config endpoint (requires session cookie) ──
    if (path === '/api/config' && req.method === 'GET') {
      const session = await validateSession(req.headers.get('cookie'), secret)
      if (!session) {
        return Response.json({ error: 'Unauthorized' }, { status: 401 })
      }

      const repo = getUserRepo()
      const user = repo.findById(session.userId)

      return Response.json({
        wsUrl: resolveWebSocketUrl(req, { publicWsUrl, wsProtocol, wsPort }),
        user: user
          ? { id: user.id, email: user.email, name: user.name, role: user.role }
          : null,
      })
    }

    // Return the default workspace ID so the webui can include it in the WS handshake
    if (path === '/api/config/workspaces' && req.method === 'GET') {
      const session = await validateSession(req.headers.get('cookie'), secret)
      if (!session) {
        return Response.json({ error: 'Unauthorized' }, { status: 401 })
      }
      const { getActiveWorkspace } = await import('@craft-agent/shared/config/storage')
      const active = getActiveWorkspace()
      return Response.json({
        defaultWorkspaceId: active?.id ?? null,
      })
    }

    // ── Everything below requires a valid session cookie ──
    const cookieHeader = req.headers.get('cookie')
    const session = await validateSession(cookieHeader, secret)

    if (!session) {
      const accept = req.headers.get('accept') ?? ''
      if (accept.includes('text/html') || path === '/' || path === '') {
        return Response.redirect('/login', 302)
      }
      return Response.json({ error: 'Unauthorized' }, { status: 401 })
    }

    // ── Serve SPA static files ──
    if (path !== '/') {
      const file = Bun.file(join(webuiDir, path))
      if (await file.exists()) {
        return new Response(file, {
          headers: { 'Content-Type': getMimeType(path) },
        })
      }
    }

    // SPA fallback — serve index.html for all non-file routes
    const indexFile = Bun.file(join(webuiDir, 'index.html'))
    if (await indexFile.exists()) {
      return new Response(indexFile, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      })
    }

    return new Response('Not Found', { status: 404 })
  }

  return {
    fetch,
    dispose: () => {
      clearInterval(cleanupTimer)
      googleFlowStore.dispose()
    },
    setOAuthCallbackDeps: (deps: OAuthCallbackDeps) => {
      options.oauthCallbackDeps = deps
    },
  }
}

// ---------------------------------------------------------------------------
// Standalone server (backwards-compatible, uses Bun.serve)
// ---------------------------------------------------------------------------

export interface WebuiHttpServerOptions extends WebuiHandlerOptions {
  /** Port to bind on. Use 0 for an ephemeral port in tests. */
  port: number
}

export async function startWebuiHttpServer(
  options: WebuiHttpServerOptions,
): Promise<{ port: number, stop: () => void }> {
  const { port, logger, ...handlerOpts } = options
  const handler = createWebuiHandler({ ...handlerOpts, logger })

  const server = Bun.serve({
    port,
    fetch: handler.fetch,
  })

  const boundPort = server.port ?? port
  logger.info(`[webui] Web UI server listening on http://0.0.0.0:${boundPort}`)

  return {
    port: boundPort,
    stop: () => {
      handler.dispose()
      server.stop()
    },
  }
}
