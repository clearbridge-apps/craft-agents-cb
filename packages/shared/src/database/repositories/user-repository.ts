import type { Database } from 'bun:sqlite';
import type { User, UserRole } from '@craft-agent/core/types';

function mapRowToUser(row: Record<string, unknown>): User {
  return {
    id: row.id as string,
    email: row.email as string,
    name: row.name as string,
    avatarUrl: row.avatar_url as string | undefined,
    googleSub: row.google_sub as string,
    role: row.role as UserRole,
    isActive: Boolean(row.is_active),
    createdAt: row.created_at as number,
    lastLoginAt: row.last_login_at as number | undefined,
  };
}

export class UserRepository {
  constructor(private db: Database) {}

  findById(id: string): User | null {
    const row = this.db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    return row ? mapRowToUser(row as Record<string, unknown>) : null;
  }

  findByEmail(email: string): User | null {
    const row = this.db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    return row ? mapRowToUser(row as Record<string, unknown>) : null;
  }

  findByGoogleSub(googleSub: string): User | null {
    const row = this.db.prepare('SELECT * FROM users WHERE google_sub = ?').get(googleSub);
    return row ? mapRowToUser(row as Record<string, unknown>) : null;
  }

  create(user: Omit<User, 'id' | 'createdAt'>): User {
    const id = crypto.randomUUID();
    const createdAt = Date.now();

    this.db
      .prepare(
        `INSERT INTO users (id, email, name, avatar_url, google_sub, role, is_active, created_at, last_login_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        id,
        user.email,
        user.name,
        user.avatarUrl ?? null,
        user.googleSub,
        user.role,
        user.isActive ? 1 : 0,
        createdAt,
        user.lastLoginAt ?? null
      );

    return {
      id,
      email: user.email,
      name: user.name,
      avatarUrl: user.avatarUrl,
      googleSub: user.googleSub,
      role: user.role,
      isActive: user.isActive,
      createdAt,
      lastLoginAt: user.lastLoginAt,
    };
  }

  updateLastLogin(id: string): void {
    this.db
      .prepare('UPDATE users SET last_login_at = ? WHERE id = ?')
      .run(Date.now(), id);
  }

  updateRole(id: string, role: UserRole): void {
    this.db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);
  }

  deactivate(id: string): void {
    this.db.prepare('UPDATE users SET is_active = 0 WHERE id = ?').run(id);
  }

  listAll(): User[] {
    const rows = this.db.prepare('SELECT * FROM users').all();
    return rows.map((row) => mapRowToUser(row as Record<string, unknown>));
  }
}
