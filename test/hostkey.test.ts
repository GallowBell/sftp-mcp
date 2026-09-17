import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import { fingerprint, matchesFingerprint, matchesKnownHosts } from '../src/hostkey.ts';

const key = Buffer.from('fake-host-key-blob');
const other = Buffer.from('other-key-blob');
const b64 = key.toString('base64');

test('fingerprint matches OpenSSH SHA256 format', () => {
  // printf test | openssl dgst -sha256 -binary | base64  ->  n4bQ...Cgg=
  assert.equal(fingerprint(Buffer.from('test')), 'SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg');
});

test('matchesFingerprint compares against pins', () => {
  assert.equal(matchesFingerprint(key, [fingerprint(other), fingerprint(key)]), true);
  assert.equal(matchesFingerprint(key, [fingerprint(other)]), false);
  assert.equal(matchesFingerprint(key, ['SHA256:short']), false);
});

test('known_hosts plain entries match host list and key', () => {
  const kh = `# comment\n\nexample.com,10.0.0.5 ssh-ed25519 ${b64}\n`;
  assert.equal(matchesKnownHosts(key, kh, 'example.com', 22), true);
  assert.equal(matchesKnownHosts(key, kh, 'EXAMPLE.com', 22), true);
  assert.equal(matchesKnownHosts(key, kh, '10.0.0.5', 22), true);
  assert.equal(matchesKnownHosts(key, kh, 'evil.com', 22), false);
  assert.equal(matchesKnownHosts(other, kh, 'example.com', 22), false);
});

test('known_hosts non-standard port uses [host]:port', () => {
  const kh = `[example.com]:2222 ssh-ed25519 ${b64}`;
  assert.equal(matchesKnownHosts(key, kh, 'example.com', 2222), true);
  assert.equal(matchesKnownHosts(key, kh, 'example.com', 22), false);
});

test('known_hosts hashed entries', () => {
  const salt = randomBytes(20);
  const hash = createHmac('sha1', salt).update('example.com').digest('base64');
  const kh = `|1|${salt.toString('base64')}|${hash} ssh-ed25519 ${b64}`;
  assert.equal(matchesKnownHosts(key, kh, 'example.com', 22), true);
  assert.equal(matchesKnownHosts(key, kh, 'example.org', 22), false);
});

test('known_hosts @revoked key always rejects', () => {
  const kh = `example.com ssh-ed25519 ${b64}\n@revoked * ssh-ed25519 ${b64}`;
  assert.equal(matchesKnownHosts(key, kh, 'example.com', 22), false);
});
