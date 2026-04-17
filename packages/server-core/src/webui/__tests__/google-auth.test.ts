import { describe, expect, it } from 'bun:test'
import {
  validateDomain,
  GoogleAuthFlowStore,
} from '../google-auth'

describe('validateDomain', () => {
  it('allows any domain when allowedDomain is not set', () => {
    expect(validateDomain('anyone@gmail.com', undefined, undefined)).toBe(true)
    expect(validateDomain('user@clearbridge.ca', 'clearbridge.ca', undefined)).toBe(true)
  })

  it('allows matching hd claim', () => {
    expect(validateDomain('user@clearbridge.ca', 'clearbridge.ca', 'clearbridge.ca')).toBe(true)
  })

  it('allows matching email domain when hd is missing', () => {
    expect(validateDomain('user@clearbridge.ca', undefined, 'clearbridge.ca')).toBe(true)
  })

  it('rejects non-matching domain', () => {
    expect(validateDomain('user@gmail.com', undefined, 'clearbridge.ca')).toBe(false)
    expect(validateDomain('user@gmail.com', 'gmail.com', 'clearbridge.ca')).toBe(false)
  })
})

describe('GoogleAuthFlowStore', () => {
  it('stores and retrieves a flow', () => {
    const store = new GoogleAuthFlowStore()
    store.store('state-abc', 'verifier-xyz')
    const flow = store.get('state-abc')
    expect(flow).not.toBeNull()
    expect(flow!.codeVerifier).toBe('verifier-xyz')
    store.dispose()
  })

  it('returns null for unknown state', () => {
    const store = new GoogleAuthFlowStore()
    expect(store.get('unknown')).toBeNull()
    store.dispose()
  })

  it('returns null for expired flow', () => {
    const store = new GoogleAuthFlowStore()
    store.store('state-abc', 'verifier-xyz')
    // Manually override createdAt to be in the past
    const flows = (store as any).flows as Map<string, { codeVerifier: string; createdAt: number }>
    const entry = flows.get('state-abc')!
    entry.createdAt = Date.now() - 6 * 60 * 1000 // 6 minutes ago
    expect(store.get('state-abc')).toBeNull()
    store.dispose()
  })

  it('cleans up expired entries', () => {
    const store = new GoogleAuthFlowStore()
    store.store('old', 'v1')
    store.store('new', 'v2')
    const flows = (store as any).flows as Map<string, { codeVerifier: string; createdAt: number }>
    flows.get('old')!.createdAt = Date.now() - 6 * 60 * 1000
    store.cleanup()
    expect(flows.has('old')).toBe(false)
    expect(flows.has('new')).toBe(true)
    store.dispose()
  })

  it('tracks size', () => {
    const store = new GoogleAuthFlowStore()
    expect(store.size).toBe(0)
    store.store('s1', 'v1')
    expect(store.size).toBe(1)
    store.remove('s1')
    expect(store.size).toBe(0)
    store.dispose()
  })
})
