import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export function fingerprint(key: Buffer): string {
  return 'SHA256:' + createHash('sha256').update(key).digest('base64').replace(/=+$/, '');
}

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export function matchesFingerprint(key: Buffer, pins: string[]): boolean {
  const fp = fingerprint(key);
  return pins.some((pin) => safeEqual(pin, fp));
}

function hostFieldMatches(field: string, name: string): boolean {
  return field.split(',').some((entry) => {
    if (entry.startsWith('|1|')) {
      const [, , salt, hash] = entry.split('|');
      if (!salt || !hash) return false;
      return safeEqual(createHmac('sha1', Buffer.from(salt, 'base64')).update(name).digest('base64'), hash);
    }
    return entry.toLowerCase() === name;
  });
}

// ponytail: wildcard (*, ?) and negated (!) host patterns are not matched; pin exact names.
export function matchesKnownHosts(key: Buffer, knownHosts: string, host: string, port: number): boolean {
  const name = port === 22 ? host.toLowerCase() : `[${host.toLowerCase()}]:${port}`;
  let found = false;
  for (const raw of knownHosts.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split(/\s+/);
    const marker = parts[0].startsWith('@') ? parts.shift() : undefined;
    const [hosts, , blob] = parts;
    if (!hosts || !blob || !key.equals(Buffer.from(blob, 'base64'))) continue;
    if (marker === '@revoked') return false;
    if (!marker && hostFieldMatches(hosts, name)) found = true;
  }
  return found;
}
