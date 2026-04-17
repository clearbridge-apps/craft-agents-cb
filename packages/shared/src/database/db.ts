import { Database } from 'bun:sqlite';
import { DB_PATH } from '../config/paths.ts';
import { runMigrations } from './migrations.ts';
import schemaSql from './schema.sql' with { type: 'text' };

let dbInstance: Database | null = null;

export function getDatabase(): Database {
  if (dbInstance) {
    return dbInstance;
  }

  dbInstance = new Database(DB_PATH);
  dbInstance.run('PRAGMA journal_mode = WAL');
  dbInstance.run('PRAGMA foreign_keys = ON');

  runMigrations(dbInstance, schemaSql);

  return dbInstance;
}
