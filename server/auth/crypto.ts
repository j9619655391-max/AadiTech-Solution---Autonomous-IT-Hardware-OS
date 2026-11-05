import { randomBytes, scrypt as scryptCallback, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
const PARAMETERS = { N: 16384, r: 8, p: 1 };
const HASH_SIZE = 64;

export function hashToken(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function newSecret(): string {
  return randomBytes(32).toString('base64url');
}

export async function hashPassword(password: string): Promise<string> {
  if (typeof password !== 'string' || password.length < 14 || Buffer.byteLength(password, 'utf8') > 1024) {
    throw new Error('Password must contain at least 14 characters and at most 1024 bytes.');
  }
  const salt = randomBytes(16);
  const derived = (await scrypt(password, salt, HASH_SIZE, PARAMETERS)) as Buffer;
  return 'scrypt:v1:' + salt.toString('hex') + ':' + derived.toString('hex');
}

export async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  if (typeof password !== 'string' || Buffer.byteLength(password, 'utf8') > 1024) return false;
  const parts = encoded.split(':');
  if (parts.length !== 4 || parts[0] !== 'scrypt' || parts[1] !== 'v1' || !/^[0-9a-f]{32}$/.test(parts[2]) || !/^[0-9a-f]{128}$/.test(parts[3])) return false;
  const expected = Buffer.from(parts[3], 'hex');
  const actual = (await scrypt(password, Buffer.from(parts[2], 'hex'), HASH_SIZE, PARAMETERS)) as Buffer;
  return timingSafeEqual(actual, expected);
}
