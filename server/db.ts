import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import type {
  AttendanceRecord,
  AuthUser,
  Professional,
  ReturnOption,
  ReturnStatus,
  ServiceItem,
  UserRole,
} from '../src/shared/catalog.ts';
import type { PayoutStatus, SetupStatus } from '../src/shared/panelTypes.ts';

const DATA_DIR = path.resolve(process.cwd(), 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, 'maiscilios.db');
export const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'professional')),
    professional TEXT NOT NULL CHECK(professional IN ('lais', 'duda')),
    password_hash TEXT NOT NULL,
    password_configured INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS attendances (
    id TEXT PRIMARY KEY,
    professional TEXT NOT NULL CHECK(professional IN ('lais', 'duda')),
    client_name TEXT NOT NULL,
    whatsapp TEXT NOT NULL,
    whatsapp_digits TEXT NOT NULL,
    service_date TEXT NOT NULL,
    services_json TEXT NOT NULL,
    additionals_json TEXT NOT NULL,
    total_paid REAL NOT NULL,
    commission_rate REAL NOT NULL,
    commission_amount REAL NOT NULL,
    return_option TEXT NOT NULL CHECK(return_option IN ('15_days', '20_days', '25_days', 'to_arrange', 'no_schedule')),
    return_days INTEGER,
    return_date TEXT,
    preferred_times_json TEXT NOT NULL,
    return_status TEXT NOT NULL CHECK(return_status IN ('waiting', 'confirmed', 'not_applicable')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS commission_payouts (
    payout_date TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK(status IN ('pending', 'paid')),
    paid_at TEXT,
    updated_by TEXT,
    updated_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_attendances_professional_date
    ON attendances(professional, service_date DESC, created_at DESC);

  CREATE INDEX IF NOT EXISTS idx_attendances_whatsapp
    ON attendances(whatsapp_digits);
`);

// Safe migration for existing databases without losing any attendance records
const userColumns = db.prepare('PRAGMA table_info(users)').all() as Array<{ name: string }>;
const hasPasswordConfigured = userColumns.some((col) => col.name === 'password_configured');
if (!hasPasswordConfigured) {
  db.exec('ALTER TABLE users ADD COLUMN password_configured INTEGER NOT NULL DEFAULT 0');
  db.exec("UPDATE users SET password_hash = '', password_configured = 0");
  db.exec('DELETE FROM sessions');
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  if (!storedHash || !storedHash.includes(':')) return false;
  const parts = storedHash.split(':');
  if (parts.length !== 2) return false;
  const [salt, keyHex] = parts;
  if (!salt || !keyHex) return false;
  const derived = crypto.scryptSync(password, salt, 64);
  const keyBuf = Buffer.from(keyHex, 'hex');
  if (derived.length !== keyBuf.length) return false;
  return crypto.timingSafeEqual(derived, keyBuf);
}

function seedUsersIfNeeded(): void {
  const existingCount = db.prepare('SELECT COUNT(*) as total FROM users').get() as { total: number };
  if (existingCount.total > 0) return;

  const now = new Date().toISOString();
  const insertUser = db.prepare(`
    INSERT INTO users (id, username, display_name, role, professional, password_hash, password_configured, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertUser.run('user_lais', 'lais', 'Laís', 'admin', 'lais', '', 0, now);
  insertUser.run('user_duda', 'duda', 'Duda', 'professional', 'duda', '', 0, now);
}

seedUsersIfNeeded();

interface DbUserRow {
  id: string;
  username: string;
  display_name: string;
  role: UserRole;
  professional: Professional;
  password_hash: string;
  password_configured: number;
}

export function getSetupStatus(): SetupStatus {
  const rows = db
    .prepare('SELECT username, password_configured FROM users')
    .all() as Array<{ username: string; password_configured: number }>;

  const lais = rows.find((r) => r.username === 'lais');
  const duda = rows.find((r) => r.username === 'duda');

  return {
    laisConfigured: Boolean(lais && lais.password_configured === 1),
    dudaConfigured: Boolean(duda && duda.password_configured === 1),
  };
}

export function findUserByUsername(username: string): DbUserRow | null {
  const row = db
    .prepare(
      'SELECT id, username, display_name, role, professional, password_hash, password_configured FROM users WHERE LOWER(username) = LOWER(?)'
    )
    .get(username.trim()) as DbUserRow | undefined;
  return row ?? null;
}

export function findUserById(userId: string): DbUserRow | null {
  const row = db
    .prepare(
      'SELECT id, username, display_name, role, professional, password_hash, password_configured FROM users WHERE id = ?'
    )
    .get(userId) as DbUserRow | undefined;
  return row ?? null;
}

export function configureInitialPassword(userId: string, password: string): boolean {
  const result = db
    .prepare(
      'UPDATE users SET password_hash = ?, password_configured = 1 WHERE id = ? AND password_configured = 0'
    )
    .run(hashPassword(password), userId);
  return result.changes > 0;
}

export function updateUserPassword(userId: string, newPassword: string): void {
  db.prepare('UPDATE users SET password_hash = ?, password_configured = 1 WHERE id = ?').run(
    hashPassword(newPassword),
    userId
  );
}

export function resetUserPasswordSetup(username: 'duda'): void {
  const row = findUserByUsername(username);
  if (!row) return;
  db.prepare("UPDATE users SET password_hash = '', password_configured = 0 WHERE id = ?").run(
    row.id
  );
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(row.id);
}

export function createSession(userId: string): { token: string; expiresAt: string } {
  const token = crypto.randomBytes(32).toString('hex');
  const now = new Date();
  const expires = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 30);
  const expiresAt = expires.toISOString();

  db.prepare(
    'INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)'
  ).run(token, userId, expiresAt, now.toISOString());

  return { token, expiresAt };
}

export function getSessionUser(token: string | undefined): AuthUser | null {
  if (!token) return null;

  const row = db
    .prepare(
      `
      SELECT u.id, u.username, u.display_name, u.role, u.professional, u.password_configured, s.expires_at
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token = ?
      `
    )
    .get(token) as
    | (Omit<DbUserRow, 'password_hash'> & { expires_at: string })
    | undefined;

  if (!row || row.password_configured !== 1) return null;

  if (new Date(row.expires_at).getTime() <= Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return null;
  }

  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    role: row.role,
    professional: row.professional,
  };
}

export function deleteSession(token: string): void {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
}

interface DbAttendanceRow {
  id: string;
  professional: Professional;
  client_name: string;
  whatsapp: string;
  whatsapp_digits: string;
  service_date: string;
  services_json: string;
  additionals_json: string;
  total_paid: number;
  commission_rate: number;
  commission_amount: number;
  return_option: ReturnOption;
  return_days: number | null;
  return_date: string | null;
  preferred_times_json: string;
  return_status: ReturnStatus;
  created_at: string;
  updated_at: string;
}

export function mapAttendanceRow(row: DbAttendanceRow): AttendanceRecord {
  let services: ServiceItem[] = [];
  let additionals: string[] = [];
  let preferredTimes: string[] = [];

  try {
    services = JSON.parse(row.services_json) as ServiceItem[];
  } catch {
    services = [];
  }

  try {
    additionals = JSON.parse(row.additionals_json) as string[];
  } catch {
    additionals = [];
  }

  try {
    preferredTimes = JSON.parse(row.preferred_times_json) as string[];
  } catch {
    preferredTimes = [];
  }

  return {
    id: row.id,
    professional: row.professional,
    clientName: row.client_name,
    whatsapp: row.whatsapp,
    whatsappDigits: row.whatsapp_digits,
    serviceDate: row.service_date,
    services,
    additionals,
    totalPaid: row.total_paid,
    commissionRate: row.commission_rate,
    commissionAmount: row.commission_amount,
    returnOption: row.return_option,
    returnDays: row.return_days,
    returnDate: row.return_date,
    preferredTimes,
    returnStatus: row.return_status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export interface InsertAttendanceInput {
  professional: Professional;
  clientName: string;
  whatsapp: string;
  whatsappDigits: string;
  serviceDate: string;
  services: ServiceItem[];
  additionals: string[];
  totalPaid: number;
  commissionRate: number;
  commissionAmount: number;
  returnOption: ReturnOption;
  returnDays: number | null;
  returnDate: string | null;
  preferredTimes: string[];
  returnStatus: ReturnStatus;
}

export function insertAttendance(input: InsertAttendanceInput): AttendanceRecord {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  db.prepare(
    `
    INSERT INTO attendances (
      id, professional, client_name, whatsapp, whatsapp_digits,
      service_date, services_json, additionals_json, total_paid,
      commission_rate, commission_amount, return_option, return_days,
      return_date, preferred_times_json, return_status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
  ).run(
    id,
    input.professional,
    input.clientName,
    input.whatsapp,
    input.whatsappDigits,
    input.serviceDate,
    JSON.stringify(input.services),
    JSON.stringify(input.additionals),
    input.totalPaid,
    input.commissionRate,
    input.commissionAmount,
    input.returnOption,
    input.returnDays,
    input.returnDate,
    JSON.stringify(input.preferredTimes),
    input.returnStatus,
    now,
    now
  );

  const created = db.prepare('SELECT * FROM attendances WHERE id = ?').get(id) as DbAttendanceRow;
  return mapAttendanceRow(created);
}

export interface AttendanceQueryFilters {
  professional?: Professional;
  startDate?: string;
  endDate?: string;
  serviceId?: string;
  search?: string;
  returnStatus?: ReturnStatus;
  onlyReturns?: boolean;
}

export function queryAttendances(filters: AttendanceQueryFilters): AttendanceRecord[] {
  const clauses: string[] = [];
  const params: Array<string | number> = [];

  if (filters.professional) {
    clauses.push('professional = ?');
    params.push(filters.professional);
  }

  if (filters.startDate) {
    clauses.push('service_date >= ?');
    params.push(filters.startDate);
  }

  if (filters.endDate) {
    clauses.push('service_date <= ?');
    params.push(filters.endDate);
  }

  if (filters.returnStatus) {
    clauses.push('return_status = ?');
    params.push(filters.returnStatus);
  }

  if (filters.onlyReturns) {
    clauses.push("return_option != 'no_schedule'");
  }

  const whereClause = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  const sql = `
    SELECT * FROM attendances
    ${whereClause}
    ORDER BY service_date DESC, created_at DESC
  `;

  const rows = db.prepare(sql).all(...params) as DbAttendanceRow[];
  let records = rows.map(mapAttendanceRow);

  if (filters.serviceId && filters.serviceId !== 'all') {
    records = records.filter((rec) =>
      rec.services.some((svc) => svc.id === filters.serviceId || svc.name === filters.serviceId)
    );
  }

  if (filters.search && filters.search.trim().length > 0) {
    const q = filters.search.trim().toLowerCase();
    const qDigits = q.replace(/\D/g, '');
    records = records.filter((rec) => {
      const nameMatch = rec.clientName.toLowerCase().includes(q);
      const phoneMatch = qDigits.length > 0 && rec.whatsappDigits.includes(qDigits);
      const rawPhoneMatch = rec.whatsapp.toLowerCase().includes(q);
      return nameMatch || phoneMatch || rawPhoneMatch;
    });
  }

  return records;
}

export function getAttendanceById(id: string): AttendanceRecord | null {
  const row = db.prepare('SELECT * FROM attendances WHERE id = ?').get(id) as
    | DbAttendanceRow
    | undefined;
  return row ? mapAttendanceRow(row) : null;
}

export function updateAttendanceReturnStatus(
  id: string,
  status: 'waiting' | 'confirmed'
): AttendanceRecord | null {
  const now = new Date().toISOString();
  db.prepare('UPDATE attendances SET return_status = ?, updated_at = ? WHERE id = ?').run(
    status,
    now,
    id
  );
  return getAttendanceById(id);
}

export function deleteAttendanceById(id: string): boolean {
  const info = db.prepare('DELETE FROM attendances WHERE id = ?').run(id);
  return info.changes > 0;
}

export interface DbCommissionPayoutRow {
  payout_date: string;
  status: PayoutStatus;
  paid_at: string | null;
  updated_by: string | null;
  updated_at: string;
}

export function getAllCommissionPayoutsMap(): Map<string, DbCommissionPayoutRow> {
  const rows = db.prepare('SELECT * FROM commission_payouts').all() as DbCommissionPayoutRow[];
  const map = new Map<string, DbCommissionPayoutRow>();
  for (const row of rows) {
    map.set(row.payout_date, row);
  }
  return map;
}

export function getCommissionPayoutByDate(date: string): DbCommissionPayoutRow | null {
  const row = db
    .prepare('SELECT * FROM commission_payouts WHERE payout_date = ?')
    .get(date) as DbCommissionPayoutRow | undefined;
  return row ?? null;
}

export function upsertCommissionPayoutStatus(
  date: string,
  status: PayoutStatus,
  updatedBy: string
): DbCommissionPayoutRow {
  const now = new Date().toISOString();
  const paidAt = status === 'paid' ? now : null;

  db.prepare(
    `
    INSERT INTO commission_payouts (payout_date, status, paid_at, updated_by, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(payout_date) DO UPDATE SET
      status = excluded.status,
      paid_at = excluded.paid_at,
      updated_by = excluded.updated_by,
      updated_at = excluded.updated_at
    `
  ).run(date, status, paidAt, updatedBy, now);

  return getCommissionPayoutByDate(date)!;
}
