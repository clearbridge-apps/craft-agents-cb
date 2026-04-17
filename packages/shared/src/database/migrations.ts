import type { Database } from 'bun:sqlite';

const MIGRATION_NAME = '001_initial_schema';

export function runMigrations(db: Database, schemaSql: string): void {
  // Ensure migrations table exists
  db.run(`
    CREATE TABLE IF NOT EXISTS migrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      applied_at INTEGER NOT NULL
    )
  `);

  const alreadyApplied = db
    .prepare('SELECT 1 FROM migrations WHERE name = ?')
    .get(MIGRATION_NAME);

  if (alreadyApplied) {
    return;
  }

  db.transaction(() => {
    db.exec(schemaSql);
    db.prepare('INSERT INTO migrations (name, applied_at) VALUES (?, ?)').run(
      MIGRATION_NAME,
      Date.now()
    );
  })();
}
