import { describe, it, expect, beforeEach } from 'bun:test';
import { Database } from 'bun:sqlite';
import { UserRepository } from '../repositories/user-repository.ts';
import { WorkspaceMemberRepository } from '../repositories/workspace-member-repository.ts';
import { runMigrations } from '../migrations.ts';
import schemaSql from '../schema.sql' with { type: 'text' };

function createTestDb(): Database {
  const db = new Database(':memory:');
  db.run('PRAGMA foreign_keys = ON');
  runMigrations(db, schemaSql);
  return db;
}

describe('WorkspaceMemberRepository', () => {
  let db: Database;
  let userRepo: UserRepository;
  let memberRepo: WorkspaceMemberRepository;

  beforeEach(() => {
    db = createTestDb();
    userRepo = new UserRepository(db);
    memberRepo = new WorkspaceMemberRepository(db);
  });

  function makeUser(email: string, googleSub: string) {
    return userRepo.create({
      email,
      name: email.split('@')[0],
      googleSub,
      role: 'user',
      isActive: true,
    });
  }

  it('adds and retrieves workspace members', () => {
    const user = makeUser('a@example.com', 'sub-a');
    const member = memberRepo.addMember({
      userId: user.id,
      workspaceId: 'ws-1',
      role: 'owner',
      addedBy: undefined,
    });

    expect(member.userId).toBe(user.id);
    expect(member.workspaceId).toBe('ws-1');
    expect(member.role).toBe('owner');
    expect(member.addedAt).toBeNumber();

    const members = memberRepo.getMembers('ws-1');
    expect(members.length).toBe(1);
    expect(members[0].userId).toBe(user.id);
    expect(members[0].user.email).toBe('a@example.com');
  });

  it('retrieves user workspaces', () => {
    const user = makeUser('b@example.com', 'sub-b');
    memberRepo.addMember({ userId: user.id, workspaceId: 'ws-1', role: 'owner' });
    memberRepo.addMember({ userId: user.id, workspaceId: 'ws-2', role: 'editor' });

    const workspaces = memberRepo.getUserWorkspaces(user.id);
    expect(workspaces.length).toBe(2);
    expect(workspaces.map((w) => w.workspaceId).sort()).toEqual(['ws-1', 'ws-2']);
  });

  it('updates member role', () => {
    const user = makeUser('c@example.com', 'sub-c');
    memberRepo.addMember({ userId: user.id, workspaceId: 'ws-1', role: 'viewer' });

    memberRepo.updateRole(user.id, 'ws-1', 'editor');
    const members = memberRepo.getMembers('ws-1');
    expect(members[0].role).toBe('editor');
  });

  it('removes a member', () => {
    const user = makeUser('d@example.com', 'sub-d');
    memberRepo.addMember({ userId: user.id, workspaceId: 'ws-1', role: 'owner' });

    memberRepo.removeMember(user.id, 'ws-1');
    expect(memberRepo.getMembers('ws-1').length).toBe(0);
    expect(memberRepo.isMember(user.id, 'ws-1')).toBe(false);
  });

  it('checks ownership', () => {
    const owner = makeUser('owner@example.com', 'sub-owner');
    const editor = makeUser('editor@example.com', 'sub-editor');

    memberRepo.addMember({ userId: owner.id, workspaceId: 'ws-1', role: 'owner' });
    memberRepo.addMember({ userId: editor.id, workspaceId: 'ws-1', role: 'editor' });

    expect(memberRepo.isOwner(owner.id, 'ws-1')).toBe(true);
    expect(memberRepo.isOwner(editor.id, 'ws-1')).toBe(false);
  });

  it('checks membership', () => {
    const user = makeUser('e@example.com', 'sub-e');
    memberRepo.addMember({ userId: user.id, workspaceId: 'ws-1', role: 'viewer' });

    expect(memberRepo.isMember(user.id, 'ws-1')).toBe(true);
    expect(memberRepo.isMember(user.id, 'ws-2')).toBe(false);
  });

  it('cascades delete when user is removed', () => {
    const user = makeUser('f@example.com', 'sub-f');
    memberRepo.addMember({ userId: user.id, workspaceId: 'ws-1', role: 'owner' });

    db.prepare('DELETE FROM users WHERE id = ?').run(user.id);

    expect(memberRepo.getMembers('ws-1').length).toBe(0);
    expect(memberRepo.isMember(user.id, 'ws-1')).toBe(false);
  });

  it('enforces primary key constraint (duplicate membership rejected)', () => {
    const user = makeUser('g@example.com', 'sub-g');
    memberRepo.addMember({ userId: user.id, workspaceId: 'ws-1', role: 'owner' });

    expect(() =>
      memberRepo.addMember({ userId: user.id, workspaceId: 'ws-1', role: 'editor' })
    ).toThrow();
  });

  it('enforces foreign key constraint (invalid user rejected)', () => {
    expect(() =>
      memberRepo.addMember({
        userId: 'nonexistent-user',
        workspaceId: 'ws-1',
        role: 'owner',
      })
    ).toThrow();
  });
});
