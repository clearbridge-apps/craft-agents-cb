import { describe, expect, it } from 'bun:test'
import {
  signJwt,
  verifyJwt,
  createSessionToken,
  createUserSessionToken,
  extractSessionCookie,
  buildSessionCookie,
  buildLogoutCookie,
  validateSession,
} from '../auth'

const SECRET = 'test-secret-key-12345678901234567890'

describe('JWT operations', () => {
  it('signs and verifies a user-aware JWT', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signJwt(
      { sub: 'user-123', email: 'test@example.com', role: 'admin', iat: now, exp: now + 3600 },
      SECRET,
    )
    expect(typeof token).toBe('string')
    expect(token.length).toBeGreaterThan(0)

    const payload = await verifyJwt(token, SECRET)
    expect(payload).not.toBeNull()
    expect(payload!.sub).toBe('user-123')
    expect(payload!.email).toBe('test@example.com')
    expect(payload!.role).toBe('admin')
  })

  it('rejects a tampered token', async () => {
    const token = await signJwt(
      { sub: 'user-123', email: 'test@example.com', role: 'admin', iat: 1000, exp: 2000 },
      SECRET,
    )
    const tampered = token.slice(0, -5) + 'xxxxx'
    const payload = await verifyJwt(tampered, SECRET)
    expect(payload).toBeNull()
  })

  it('rejects a token with wrong secret', async () => {
    const token = await signJwt(
      { sub: 'user-123', email: 'test@example.com', role: 'admin', iat: 1000, exp: 2000 },
      SECRET,
    )
    const payload = await verifyJwt(token, 'wrong-secret')
    expect(payload).toBeNull()
  })
})

describe('createSessionToken (legacy)', () => {
  it('creates a token with sub=webui', async () => {
    const token = await createSessionToken(SECRET)
    const payload = await verifyJwt(token, SECRET)
    expect(payload).not.toBeNull()
    expect(payload!.sub).toBe('webui')
    expect(payload!.email).toBe('webui@local')
    expect(payload!.role).toBe('admin')
  })
})

describe('createUserSessionToken', () => {
  it('creates a token with user identity', async () => {
    const user = {
      id: 'user-456',
      email: 'alice@example.com',
      name: 'Alice',
      googleSub: 'google-123',
      role: 'user' as const,
      isActive: true,
      createdAt: Date.now(),
    }
    const token = await createUserSessionToken(SECRET, user)
    const payload = await verifyJwt(token, SECRET)
    expect(payload).not.toBeNull()
    expect(payload!.sub).toBe('user-456')
    expect(payload!.email).toBe('alice@example.com')
    expect(payload!.role).toBe('user')
  })
})

describe('Cookie helpers', () => {
  it('builds a session cookie without Secure', () => {
    const cookie = buildSessionCookie('my-jwt', false)
    expect(cookie).toContain('craft_session=my-jwt')
    expect(cookie).toContain('HttpOnly')
    expect(cookie).toContain('SameSite=Strict')
    expect(cookie).not.toContain('Secure')
  })

  it('builds a session cookie with Secure', () => {
    const cookie = buildSessionCookie('my-jwt', true)
    expect(cookie).toContain('Secure')
  })

  it('builds a logout cookie', () => {
    const cookie = buildLogoutCookie()
    expect(cookie).toContain('craft_session=')
    expect(cookie).toContain('Max-Age=0')
  })

  it('extracts session cookie from header', () => {
    expect(extractSessionCookie('craft_session=abc123; other=value')).toBe('abc123')
    expect(extractSessionCookie('other=value; craft_session=xyz')).toBe('xyz')
    expect(extractSessionCookie(null)).toBeNull()
    expect(extractSessionCookie('other=value')).toBeNull()
  })
})

describe('validateSession', () => {
  it('returns user info for valid session', async () => {
    const user = {
      id: 'user-789',
      email: 'bob@example.com',
      name: 'Bob',
      googleSub: 'google-456',
      role: 'admin' as const,
      isActive: true,
      createdAt: Date.now(),
    }
    const token = await createUserSessionToken(SECRET, user)
    const cookieHeader = `craft_session=${token}`
    const session = await validateSession(cookieHeader, SECRET)
    expect(session).not.toBeNull()
    expect(session!.userId).toBe('user-789')
    expect(session!.email).toBe('bob@example.com')
    expect(session!.role).toBe('admin')
  })

  it('returns null for missing cookie', async () => {
    const session = await validateSession(null, SECRET)
    expect(session).toBeNull()
  })

  it('returns null for invalid cookie', async () => {
    const session = await validateSession('craft_session=bad-token', SECRET)
    expect(session).toBeNull()
  })
})
