import type { Database } from 'bun:sqlite';
import type { User, WorkspaceMember } from '@craft-agent/core/types';
import { UserRepository } from './user-repository.ts';

function mapRowToWorkspaceMember(row: Record<string, unknown>): WorkspaceMember {
  return {
    userId: row.user_id as string,
    workspaceId: row.workspace_id as string,
    role: row.role as WorkspaceMember['role'],
    addedAt: row.added_at as number,
    addedBy: row.added_by as string | undefined,
  };
}

export class WorkspaceMemberRepository {
  constructor(private db: Database) {}

  getMembers(workspaceId: string): (WorkspaceMember & { user: User })[] {
    const rows = this.db
      .prepare(
        `SELECT wm.*, u.id as u_id, u.email as u_email, u.name as u_name,
                u.avatar_url as u_avatar_url, u.google_sub as u_google_sub,
                u.role as u_role, u.is_active as u_is_active,
                u.created_at as u_created_at, u.last_login_at as u_last_login_at
         FROM workspace_members wm
         JOIN users u ON wm.user_id = u.id
         WHERE wm.workspace_id = ?`
      )
      .all(workspaceId);

    return rows.map((row) => {
      const r = row as Record<string, unknown>;
      const user: User = {
        id: r.u_id as string,
        email: r.u_email as string,
        name: r.u_name as string,
        avatarUrl: r.u_avatar_url as string | undefined,
        googleSub: r.u_google_sub as string,
        role: r.u_role as User['role'],
        isActive: Boolean(r.u_is_active),
        createdAt: r.u_created_at as number,
        lastLoginAt: r.u_last_login_at as number | undefined,
      };
      return {
        userId: r.user_id as string,
        workspaceId: r.workspace_id as string,
        role: r.role as WorkspaceMember['role'],
        addedAt: r.added_at as number,
        addedBy: r.added_by as string | undefined,
        user,
      };
    });
  }

  getUserWorkspaces(userId: string): WorkspaceMember[] {
    const rows = this.db
      .prepare('SELECT * FROM workspace_members WHERE user_id = ?')
      .all(userId);
    return rows.map((row) => mapRowToWorkspaceMember(row as Record<string, unknown>));
  }

  addMember(member: Omit<WorkspaceMember, 'addedAt'>): WorkspaceMember {
    const addedAt = Date.now();
    this.db
      .prepare(
        `INSERT INTO workspace_members (user_id, workspace_id, role, added_at, added_by)
         VALUES (?, ?, ?, ?, ?)`
      )
      .run(
        member.userId,
        member.workspaceId,
        member.role,
        addedAt,
        member.addedBy ?? null
      );

    return {
      ...member,
      addedAt,
    };
  }

  removeMember(userId: string, workspaceId: string): void {
    this.db
      .prepare(
        'DELETE FROM workspace_members WHERE user_id = ? AND workspace_id = ?'
      )
      .run(userId, workspaceId);
  }

  updateRole(userId: string, workspaceId: string, role: string): void {
    this.db
      .prepare(
        'UPDATE workspace_members SET role = ? WHERE user_id = ? AND workspace_id = ?'
      )
      .run(role, userId, workspaceId);
  }

  isMember(userId: string, workspaceId: string): boolean {
    const row = this.db
      .prepare(
        'SELECT 1 FROM workspace_members WHERE user_id = ? AND workspace_id = ?'
      )
      .get(userId, workspaceId);
    return row !== null;
  }

  isOwner(userId: string, workspaceId: string): boolean {
    const row = this.db
      .prepare(
        `SELECT 1 FROM workspace_members WHERE user_id = ? AND workspace_id = ? AND role = 'owner'`
      )
      .get(userId, workspaceId);
    return row !== null;
  }
}
