import { randomBytes, createHash } from 'crypto';

export function generateSalt(bytes = 16): string {
  return randomBytes(bytes).toString('base64');
}

export function hashPin(pin: string, saltBase64: string): string {
  const hash = createHash('sha256');
  const salt = Buffer.from(saltBase64, 'base64');
  hash.update(salt);
  hash.update(Buffer.from(pin, 'utf8'));
  return hash.digest('base64');
}



