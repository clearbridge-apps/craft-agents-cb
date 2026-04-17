import { describe, it, expect, beforeEach } from 'bun:test';
import { Database } from 'bun:sqlite';
import { UserRepository } from '../repositories/user-repository.ts';
import { runMigrations } from '../migrations.ts';
import schemaSql from '../schema.sql' with { type: 'text' };

function createTestDb(): Database {
  const db = new Database(':memory:');
  db.run('PRAGMA foreign_keys = ON');
  runMigrations(db, schemaSql);
  return db;
}

describe('UserRepository', () => {
  let db: Database;
  let repo: UserRepository;

  beforeEach(() => {
    db = createTestDb();
    repo = new UserRepository(db);
  });

  it('creates and finds a user by id', () => {
    const user = repo.create({
      email: 'alice@example.com',
      name: 'Alice',
      googleSub: 'google-1',
      role: 'user',
      isActive: true,
    });

    expect(user.id).toBeString();
    expect(user.createdAt).toBeNumber();
    expect(user.email).toBe('alice@example.com');

    const found = repo.findById(user.id);
    expect(found).not.toBeNull();
    expect(found!.email).toBe('alice@example.com');
    expect(found!.name).toBe('Alice');
    expect(found!.googleSub).toBe('google-1');
    expect(found!.role).toBe('user');
    expect(found!.isActive).toBe(true);
  });

  it('finds a user by email', () => {
    repo.create({
      email: 'bob@example.com',
      name: 'Bob',
      googleSub: 'google-2',
      role: 'admin',
      isActive: true,
    });

    const found = repo.findByEmail('bob@example.com');
    expect(found).not.toBeNull();
    expect(found!.name).toBe('Bob');
  });

  it('finds a user by googleSub', () => {
    repo.create({
      email: 'carol@example.com',
      name: 'Carol',
      googleSub: 'google-3',
      role: 'user',
      isActive: false,
    });

    const found = repo.findByGoogleSub('google-3');
    expect(found).not.toBeNull();
    expect(found!.name).toBe('Carol');
    expect(found!.isActive).toBe(false);
  });

  it('returns null when user not found', () => {
    expect(repo.findById('nonexistent')).toBeNull();
    expect(repo.findByEmail('nobody@example.com')).toBeNull();
    expect(repo.findByGoogleSub('no-sub')).toBeNull();
  });

  it('enforces unique email constraint', () => {
    repo.create({
      email: 'dup@example.com',
      name: 'First',
      googleSub: 'sub-a',
      role: 'user',
      isActive: true,
    });

    expect(() =>
      repo.create({
        email: 'dup@example.com',
        name: 'Second',
        googleSub: 'sub-b',
        role: 'user',
        isActive: true,
      })
    ).toThrow();
  });

  it('enforces unique googleSub constraint', () => {
    repo.create({
      email: 'a@example.com',
      name: 'First',
      googleSub: 'same-sub',
      role: 'user',
      isActive: true,
    });

    expect(() =>
      repo.create({
        email: 'b@example.com',
        name: 'Second',
        googleSub: 'same-sub',
        role: 'user',
        isActive: true,
      })
    ).toThrow();
  });

  it('updates lastLoginAt', () => {
    const user = repo.create({
      email: 'login@example.com',
      name: 'Login',
      googleSub: 'sub-login',
      role: 'user',
      isActive: true,
    });

    expect(user.lastLoginAt).toBeUndefined();

    repo.updateLastLogin(user.id);
    const found = repo.findById(user.id);
    expect(found!.lastLoginAt).toBeNumber();
    expect(found!.lastLoginAt!).toBeGreaterThanOrEqual(user.createdAt);
  });

  it('updates role', () => {
    const user = repo.create({
      email: 'role@example.com',
      name: 'Role',
      googleSub: 'sub-role',
      role: 'user',
      isActive: true,
    });

    repo.updateRole(user.id, 'admin');
    const found = repo.findById(user.id);
    expect(found!.role).toBe('admin');
  });

  it('deactivates a user', () => {
    const user = repo.create({
      email: 'deact@example.com',
      name: 'Deact',
      googleSub: 'sub-deact',
      role: 'user',
      isActive: true,
    });

    repo.deactivate(user.id);
    const found = repo.findById(user.id);
    expect(found!.isActive).toBe(false);
  });

  it('lists all users', () => {
    repo.create({
      email: 'u1@example.com',
      name: 'U1',
      googleSub: 'sub-1',
      role: 'user',
      isActive: true,
    });
    repo.create({
      email: 'u2@example.com',
      name: 'U2',
      googleSub: 'sub-2',
      role: 'admin',
      isActive: true,
    });

    const all = repo.listAll();
    expect(all.length).toBe(2);
    expect(all.map((u) => u.email).sort()).toEqual(['u1@example.com', 'u2@example.com']);
  });
});
