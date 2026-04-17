import { afterEach, describe, expect, it } from 'bun:test'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { startWebuiHttpServer } from '../http-server'

const SECRET = 'test-server-secret'
const PASSWORD = 'test-password'
const TEMP_DIRS: string[] = []
const SERVERS: Array<{ stop: () => void }> = []

const logger = {
  info: () => {},
  warn: () => {},
  error: () => {},
  debug: () => {},
} as any

function createTestWebuiDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'craft-webui-test-'))
  TEMP_DIRS.push(dir)
  writeFileSync(join(dir, 'login.html'), '<!doctype html><html><body>login</body></html>')
  writeFileSync(join(dir, 'index.html'), '<!doctype html><html><body>app</body></html>')
  return dir
}

async function createServer(overrides?: {
  secureCookies?: boolean
  publicWsUrl?: string
  wsProtocol?: 'ws' | 'wss'
  wsPort?: number
  googleAuthConfig?: {
    clientId: string
    clientSecret: string
    redirectUri: string
    allowedDomain?: string
  }
}) {
  const server = await startWebuiHttpServer({
    port: 0,
    webuiDir: createTestWebuiDir(),
    secret: SECRET,
    password: PASSWORD,
    secureCookies: overrides?.secureCookies,
    publicWsUrl: overrides?.publicWsUrl,
    wsProtocol: overrides?.wsProtocol ?? 'wss',
    wsPort: overrides?.wsPort ?? 9100,
    getHealthCheck: () => ({ status: 'ok' }),
    logger,
    googleAuthConfig: overrides?.googleAuthConfig,
  })

  SERVERS.push(server)

  return {
    server,
    baseUrl: `http://127.0.0.1:${server.port}`,
  }
}

function extractSessionCookie(res: Response): string {
  const setCookie = res.headers.get('set-cookie')
  expect(setCookie).toBeTruthy()
  return setCookie!.split(';')[0]!
}

afterEach(() => {
  while (SERVERS.length > 0) {
    SERVERS.pop()?.stop()
  }

  while (TEMP_DIRS.length > 0) {
    const dir = TEMP_DIRS.pop()
    if (dir) rmSync(dir, { recursive: true, force: true })
  }
})

describe('startWebuiHttpServer', () => {
  it('allows plain-http login even when the RPC transport is wss', async () => {
    const { baseUrl } = await createServer({ wsProtocol: 'wss', wsPort: 9100 })

    const authRes = await fetch(`${baseUrl}/api/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: PASSWORD }),
    })

    expect(authRes.status).toBe(200)
    const setCookie = authRes.headers.get('set-cookie')
    expect(setCookie).toContain('craft_session=')
    expect(setCookie).not.toContain('Secure')

    const configRes = await fetch(`${baseUrl}/api/config`, {
      headers: {
        cookie: extractSessionCookie(authRes),
      },
    })

    expect(configRes.status).toBe(200)
    const config = await configRes.json()
    expect(config.wsUrl).toBe('wss://127.0.0.1:9100')
    expect(config.user).toBeNull() // no user in DB for legacy password auth
  })

  it('rejects invalid credentials', async () => {
    const { baseUrl } = await createServer()

    const res = await fetch(`${baseUrl}/api/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'wrong-password' }),
    })

    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'Invalid credentials' })
  })

  it('honors an explicit secure-cookie override', async () => {
    const { baseUrl } = await createServer({ secureCookies: true, wsProtocol: 'ws', wsPort: 9100 })

    const res = await fetch(`${baseUrl}/api/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: PASSWORD }),
    })

    expect(res.status).toBe(200)
    expect(res.headers.get('set-cookie')).toContain('Secure')
  })

  it('infers secure cookies from proxy https headers when no override is set', async () => {
    const { baseUrl } = await createServer({ wsProtocol: 'wss', wsPort: 9100 })

    const res = await fetch(`${baseUrl}/api/auth`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-Proto': 'https',
      },
      body: JSON.stringify({ password: PASSWORD }),
    })

    expect(res.status).toBe(200)
    expect(res.headers.get('set-cookie')).toContain('Secure')
  })

  it('derives a browser-facing websocket URL from forwarded public host headers', async () => {
    const { baseUrl } = await createServer({ wsProtocol: 'wss', wsPort: 9100 })

    const authRes = await fetch(`${baseUrl}/api/auth`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-Proto': 'https',
        'X-Forwarded-Host': 'craft.example.com:3100',
      },
      body: JSON.stringify({ password: PASSWORD }),
    })

    const configRes = await fetch(`${baseUrl}/api/config`, {
      headers: {
        cookie: extractSessionCookie(authRes),
        'X-Forwarded-Proto': 'https',
        'X-Forwarded-Host': 'craft.example.com:3100',
      },
    })

    expect(configRes.status).toBe(200)
    const config = await configRes.json()
    expect(config.wsUrl).toBe('wss://craft.example.com:9100')
  })

  it('returns an explicit public websocket URL override from /api/config', async () => {
    const { baseUrl } = await createServer({
      publicWsUrl: 'wss://craft.example.com/ws',
      wsProtocol: 'wss',
      wsPort: 9100,
    })

    const authRes = await fetch(`${baseUrl}/api/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: PASSWORD }),
    })

    const configRes = await fetch(`${baseUrl}/api/config`, {
      headers: {
        cookie: extractSessionCookie(authRes),
      },
    })

    expect(configRes.status).toBe(200)
    const config = await configRes.json()
    expect(config.wsUrl).toBe('wss://craft.example.com/ws')
  })
})

describe('/api/auth/providers', () => {
  it('returns google=false when not configured', async () => {
    const { baseUrl } = await createServer()

    const res = await fetch(`${baseUrl}/api/auth/providers`)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body).toEqual({ google: false, password: true })
  })

  it('returns google=true when configured', async () => {
    const { baseUrl } = await createServer({
      googleAuthConfig: {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost/callback',
      },
    })

    const res = await fetch(`${baseUrl}/api/auth/providers`)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body).toEqual({ google: true, password: true })
  })
})

describe('/api/auth/google', () => {
  it('returns 404 when Google auth is not configured', async () => {
    const { baseUrl } = await createServer()

    const res = await fetch(`${baseUrl}/api/auth/google`, { redirect: 'manual' })
    expect(res.status).toBe(404)
  })

  it('redirects to Google when configured', async () => {
    const { baseUrl } = await createServer({
      googleAuthConfig: {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost/callback',
      },
    })

    const res = await fetch(`${baseUrl}/api/auth/google`, { redirect: 'manual' })
    expect(res.status).toBe(302)
    const location = res.headers.get('location')
    expect(location).toBeTruthy()
    expect(location).toContain('accounts.google.com')
    expect(location).toContain('client_id=test-client-id')
    expect(location).toContain('response_type=code')
    expect(location).toContain('code_challenge=')
    expect(location).toContain('code_challenge_method=S256')
    expect(location).toContain('scope=openid+email+profile')
  })
})

describe('/api/auth/google/callback', () => {
  it('returns 404 when Google auth is not configured', async () => {
    const { baseUrl } = await createServer()

    const res = await fetch(`${baseUrl}/api/auth/google/callback?code=abc&state=xyz`)
    expect(res.status).toBe(404)
  })

  it('renders error page for missing code/state', async () => {
    const { baseUrl } = await createServer({
      googleAuthConfig: {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost/callback',
      },
    })

    const res = await fetch(`${baseUrl}/api/auth/google/callback`)
    expect(res.status).toBe(400)
    const text = await res.text()
    expect(text).toContain('Missing code or state parameter')
  })

  it('renders error page for invalid/expired state', async () => {
    const { baseUrl } = await createServer({
      googleAuthConfig: {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost/callback',
      },
    })

    const res = await fetch(`${baseUrl}/api/auth/google/callback?code=abc&state=invalid-state`)
    expect(res.status).toBe(400)
    const text = await res.text()
    expect(text).toContain('OAuth flow expired or invalid state')
  })
})

describe('/api/auth/me', () => {
  it('returns 401 without session', async () => {
    const { baseUrl } = await createServer()

    const res = await fetch(`${baseUrl}/api/auth/me`)
    expect(res.status).toBe(401)
  })

  it('returns 404 for legacy password session (no user in DB)', async () => {
    const { baseUrl } = await createServer()

    const authRes = await fetch(`${baseUrl}/api/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: PASSWORD }),
    })

    const res = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { cookie: extractSessionCookie(authRes) },
    })
    expect(res.status).toBe(404)
  })
})
