export type UserRole = 'admin' | 'user';

export interface User {
  id: string; // UUID
  email: string; // Google email (unique)
  name: string; // Display name from Google profile
  avatarUrl?: string; // Google profile picture URL
  googleSub: string; // Google subject ID (unique, stable identifier)
  role: UserRole;
  isActive: boolean; // Soft-disable accounts
  createdAt: number; // Unix timestamp ms
  lastLoginAt?: number; // Unix timestamp ms
}

export interface WorkspaceMember {
  userId: string;
  workspaceId: string;
  role: 'owner' | 'editor' | 'viewer';
  addedAt: number;
  addedBy?: string; // userId of who granted access
}
