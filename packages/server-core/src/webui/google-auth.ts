/**
 * Google OAuth 2.0 / OIDC authentication for the Web UI.
 *
 * Handles the authorization-code flow with PKCE:
 *   1. generateAuthUrl() → redirects browser to Google consent screen
 *   2. exchangeCodeForTokens() → POST to Google token endpoint
 *   3. verifyIdToken() → validate JWT signature via Google's JWKS
 *
 * Pending flows are stored in-memory with a 5-minute TTL (CSRF protection).
 */

import { createRemoteJWKSet, jwtVerify } from 'jose'

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface GoogleAuthConfig {
  clientId: string
  clientSecret: string
  redirectUri: string
  allowedDomain?: string
}

export interface GoogleTokenResponse {
  accessToken: string
  idToken: string
  refreshToken?: string
  expiresIn?: number
}

export interface GoogleUserInfo {
  sub: string
  email: string
  name: string
  picture?: string
  emailVerified: boolean
  hd?: string
}

// ---------------------------------------------------------------------------
// PKCE helpers
// ---------------------------------------------------------------------------

function generateState(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

function generateCodeVerifier(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return base64urlEncode(bytes)
}

async function sha256(plain: string): Promise<ArrayBuffer> {
  const encoder = new TextEncoder()
  const data = encoder.encode(plain)
  return crypto.subtle.digest('SHA-256', data)
}

function base64urlEncode(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer
  const binary = Array.from(bytes, b => String.fromCharCode(b)).join('')
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// ---------------------------------------------------------------------------
// Auth URL generation
// ---------------------------------------------------------------------------

export async function generateAuthUrl(
  config: GoogleAuthConfig,
): Promise<{ url: string; state: string; codeVerifier: string }> {
  const state = generateState()
  const codeVerifier = generateCodeVerifier()
  const codeChallenge = base64urlEncode(await sha256(codeVerifier))

  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth')
  url.searchParams.set('client_id', config.clientId)
  url.searchParams.set('redirect_uri', config.redirectUri)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('scope', 'openid email profile')
  url.searchParams.set('state', state)
  url.searchParams.set('code_challenge', codeChallenge)
  url.searchParams.set('code_challenge_method', 'S256')
  url.searchParams.set('access_type', 'offline')
  url.searchParams.set('prompt', 'consent')

  return { url: url.toString(), state, codeVerifier }
}

// ---------------------------------------------------------------------------
// Token exchange
// ---------------------------------------------------------------------------

export async function exchangeCodeForTokens(
  config: GoogleAuthConfig,
  code: string,
  codeVerifier: string,
): Promise<GoogleTokenResponse> {
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.redirectUri,
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code_verifier: codeVerifier,
  })

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  })

  if (!response.ok) {
    const text = await response.text()
    throw new Error(`Google token exchange failed: ${text}`)
  }

  const data = (await response.json()) as {
    access_token: string
    id_token: string
    refresh_token?: string
    expires_in?: number
  }

  return {
    accessToken: data.access_token,
    idToken: data.id_token,
    refreshToken: data.refresh_token,
    expiresIn: data.expires_in,
  }
}

// ---------------------------------------------------------------------------
// ID token verification (OIDC)
// ---------------------------------------------------------------------------

const GOOGLE_JWKS_URI = 'https://www.googleapis.com/oauth2/v3/certs'
let remoteJWKSet: ReturnType<typeof createRemoteJWKSet> | null = null

function getRemoteJWKSet() {
  if (!remoteJWKSet) {
    remoteJWKSet = createRemoteJWKSet(new URL(GOOGLE_JWKS_URI))
  }
  return remoteJWKSet
}

export async function verifyIdToken(
  idToken: string,
  clientId: string,
): Promise<GoogleUserInfo> {
  const { payload } = await jwtVerify(idToken, getRemoteJWKSet(), {
    issuer: ['https://accounts.google.com', 'accounts.google.com'],
    audience: clientId,
    clockTolerance: 60,
  })

  const sub = payload.sub
  const email = payload.email as string | undefined
  const name = (payload.name as string | undefined) || email || 'Unknown'
  const picture = payload.picture as string | undefined
  const emailVerified = payload.email_verified === true
  const hd = payload.hd as string | undefined

  if (!sub || !email) {
    throw new Error('ID token missing required claims (sub, email)')
  }

  return { sub, email, name, picture, emailVerified, hd }
}

// ---------------------------------------------------------------------------
// Domain validation
// ---------------------------------------------------------------------------

export function validateDomain(
  email: string,
  hd: string | undefined,
  allowedDomain: string | undefined,
): boolean {
  if (!allowedDomain) return true
  if (hd === allowedDomain) return true
  const domain = email.split('@')[1]
  if (domain === allowedDomain) return true
  return false
}

// ---------------------------------------------------------------------------
// Pending flow store (in-memory, 5-min TTL)
// ---------------------------------------------------------------------------

interface PendingFlow {
  codeVerifier: string
  createdAt: number
}

const FLOW_TTL_MS = 5 * 60 * 1000 // 5 minutes
const CLEANUP_INTERVAL_MS = 60 * 1000 // 1 minute

export class GoogleAuthFlowStore {
  private flows = new Map<string, PendingFlow>()
  private cleanupTimer: ReturnType<typeof setInterval> | null = null

  constructor() {
    this.cleanupTimer = setInterval(() => this.cleanup(), CLEANUP_INTERVAL_MS)
  }

  store(state: string, codeVerifier: string): void {
    this.flows.set(state, { codeVerifier, createdAt: Date.now() })
  }

  get(state: string): PendingFlow | null {
    const flow = this.flows.get(state)
    if (!flow) return null
    if (Date.now() - flow.createdAt > FLOW_TTL_MS) {
      this.flows.delete(state)
      return null
    }
    return flow
  }

  remove(state: string): void {
    this.flows.delete(state)
  }

  cleanup(): void {
    const now = Date.now()
    for (const [state, flow] of this.flows) {
      if (now - flow.createdAt > FLOW_TTL_MS) {
        this.flows.delete(state)
      }
    }
  }

  dispose(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer)
      this.cleanupTimer = null
    }
    this.flows.clear()
  }

  get size(): number {
    return this.flows.size
  }
}
