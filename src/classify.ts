// Fail-closed field classification per ADR-0003 / ADR-0010 / CONTEXT.md.
// Gate on 1Password's own type/purpose, never on label text - then gate again
// on the value itself, because `STRING` says nothing about content (ADR-0010).

import assert from 'node:assert/strict';

const SAFE_TYPES = new Set(['STRING', 'URL', 'EMAIL', 'PHONE', 'ADDRESS']);
const SAFE_PURPOSES = new Set(['USERNAME']);
const ALWAYS_SENSITIVE_PURPOSES = new Set(['NOTES', 'PASSWORD']);

export interface OpField {
  type?: string;
  purpose?: string;
  value?: unknown;
}

// Structural markers. Anything matching is credential material regardless of
// which field widget it was pasted into.
const SECRET_MARKERS: Array<[RegExp, string]> = [
  [/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/, 'pem-private-key'],
  [/-----BEGIN [A-Z0-9 ]*(?:KEY|CERTIFICATE|PARAMETERS)-----/, 'pem-block'],
  [/\bPuTTY-User-Key-File\b/, 'putty-key'],
  [/^ssh-(?:rsa|dss|ed25519)\s+AAAA[0-9A-Za-z+/]+/, 'ssh-key-blob'],
  [/^ecdsa-sha2-nistp\d+\s+AAAA[0-9A-Za-z+/]+/, 'ssh-key-blob'],
  // Vendor-prefixed tokens. Prefixes are deliberately literal - these are
  // published formats, not guesses.
  [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}/, 'github-token'],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}/, 'github-pat'],
  [/\bglpat-[A-Za-z0-9_-]{16,}/, 'gitlab-token'],
  [/\bxox[abposr]-[A-Za-z0-9-]{10,}/, 'slack-token'],
  [/\bsk-[A-Za-z0-9_-]{20,}/, 'openai-style-token'],
  [/\bAKIA[0-9A-Z]{16}\b/, 'aws-access-key-id'],
  [/\bASIA[0-9A-Z]{16}\b/, 'aws-temp-key-id'],
  [/\bAIza[0-9A-Za-z_-]{35}\b/, 'google-api-key'],
  [/\bnpm_[A-Za-z0-9]{36}\b/, 'npm-token'],
  [/\bdop_v1_[a-f0-9]{64}\b/, 'digitalocean-token'],
  [/\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/, 'sendgrid-key'],
  // JWT: three base64url segments, first decoding to a JSON header.
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/, 'jwt'],
  // Credentials embedded in a connection string, e.g. postgres://u:pw@host/db
  [/^[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@/i, 'uri-with-credentials'],
];

// Shapes that are legitimately part of this project's safe-value vocabulary
// (CONTEXT.md: username, URL, hostname, port). Checked before the entropy
// heuristic so a long hostname or URL is never mistaken for a blob.
const KNOWN_SAFE_SHAPES: RegExp[] = [
  /^[a-z][a-z0-9+.-]*:\/\/\S*$/i,                        // URL, no embedded credentials
  /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/,    // email
  /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\.?$/,              // dotted hostname
  /^\d{1,3}(?:\.\d{1,3}){3}$/,                           // IPv4
  /^[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}$/i,             // IPv6
  /^\d{1,5}$/,                                           // port
  /^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9.-]+$/,               // user@host
];

const HIGH_ENTROPY_LENGTH = 32;

// Undelimited blobs: long, no whitespace, drawn from a base64/hex/base58-ish
// alphabet. Anything with spaces reads as prose, not a key.
const BLOB_SHAPES: Array<[RegExp, string]> = [
  [new RegExp(`^[0-9a-f]{${HIGH_ENTROPY_LENGTH},}$`, 'i'), 'hex-blob'],
  [new RegExp(`^[A-Za-z0-9+/]{${HIGH_ENTROPY_LENGTH},}={0,2}$`), 'base64-blob'],
  [new RegExp(`^[A-Za-z0-9_-]{${HIGH_ENTROPY_LENGTH},}$`), 'token-blob'],
];

/**
 * Why a value was judged secret, or null if nothing matched.
 *
 * A heuristic, not a boundary - see ADR-0010. The hard guarantees remain the
 * type/purpose allowlist and dropping notes outright.
 */
export function secretReason(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const v = value.trim();
  if (v === '') return null;

  for (const [re, reason] of SECRET_MARKERS) {
    if (re.test(v)) return reason;
  }

  // Multi-line free text in a single-line field type is unexpected; treat a
  // pasted block as suspect rather than passing it through.
  if (/\r?\n/.test(v)) return 'multiline-block';

  if (KNOWN_SAFE_SHAPES.some((re) => re.test(v))) return null;

  for (const [re, reason] of BLOB_SHAPES) {
    if (re.test(v)) return reason;
  }

  return null;
}

export function looksSecret(value: unknown): boolean {
  return secretReason(value) !== null;
}

// An unsafe type vetoes a safe purpose (issue #5). Previously a safe purpose
// returned early, so { type: 'SSHKEY', purpose: 'USERNAME' } was classified
// safe. When the two signals disagree, take the cautious one - that is what
// fail-closed means, and it removes a case where the guarantee rested on
// 1Password never emitting such a combination.
function typeAllows(field: OpField): boolean {
  if (field.purpose && ALWAYS_SENSITIVE_PURPOSES.has(field.purpose)) return false;
  const typeIsSafe = !field.type || SAFE_TYPES.has(field.type);
  if (field.purpose && SAFE_PURPOSES.has(field.purpose)) return typeIsSafe;
  return !!field.type && SAFE_TYPES.has(field.type);
}

export function isFieldSafe(field: OpField): boolean {
  if (!typeAllows(field)) return false;
  // Second gate: the type said safe, but the content may not be (ADR-0010).
  return !looksSecret(field.value);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  // --- type/purpose gate (unchanged behaviour) ---
  assert.strictEqual(isFieldSafe({ type: 'STRING' }), true, 'STRING should be safe');
  assert.strictEqual(isFieldSafe({ type: 'CONCEALED' }), false, 'CONCEALED should be sensitive');
  assert.strictEqual(isFieldSafe({ type: 'SSHKEY' }), false, 'SSHKEY should be sensitive');
  assert.strictEqual(isFieldSafe({ type: 'STRING', purpose: 'PASSWORD' }), false, 'PASSWORD purpose is sensitive even as STRING');
  assert.strictEqual(isFieldSafe({ type: 'STRING', purpose: 'NOTES' }), false, 'NOTES purpose is always sensitive');
  assert.strictEqual(isFieldSafe({ purpose: 'USERNAME' }), true, 'USERNAME purpose is safe');
  assert.strictEqual(isFieldSafe({}), false, 'unknown/missing type fails closed');
  assert.strictEqual(isFieldSafe({ type: 'OTP' }), false, 'unrecognised type fails closed');
  assert.strictEqual(isFieldSafe({ type: 'CREDIT_CARD_NUMBER' }), false, 'card number fails closed');
  assert.strictEqual(isFieldSafe({ type: 'string' }), false, 'type match is case-sensitive, lowercase fails closed');
  assert.strictEqual(isFieldSafe({ purpose: 'username' }), false, 'purpose match is case-sensitive, lowercase fails closed');

  // --- an unsafe type vetoes a safe purpose (issue #5) ---
  assert.strictEqual(isFieldSafe({ type: 'SSHKEY', purpose: 'USERNAME' }), false, 'SSHKEY type vetoes USERNAME purpose');
  assert.strictEqual(isFieldSafe({ type: 'CONCEALED', purpose: 'USERNAME' }), false, 'CONCEALED type vetoes USERNAME purpose');
  assert.strictEqual(isFieldSafe({ type: 'OTP', purpose: 'USERNAME' }), false, 'unrecognised type vetoes USERNAME purpose');
  assert.strictEqual(isFieldSafe({ type: 'STRING', purpose: 'USERNAME' }), true, 'safe type and safe purpose still pass');
  assert.strictEqual(isFieldSafe({ type: 'EMAIL', purpose: 'USERNAME' }), true, 'email-typed username still passes');
  assert.strictEqual(isFieldSafe({ purpose: 'USERNAME' }), true, 'safe purpose with no type still passes');
  // Precedence between the two purpose sets is unchanged: sensitive wins.
  assert.strictEqual(isFieldSafe({ type: 'STRING', purpose: 'PASSWORD' }), false, 'sensitive purpose still beats safe type');

  // --- safe values must still pass: this is the project's whole point ---
  const safeValues = [
    'prod.example.com',
    'drupal-ci.maint.example.com',
    'https://example.com/wp-admin',
    'ssh://box.example.com:22222',
    'deploy',
    'deploy@prod.example.com',
    'ops@example.com',
    '22222',
    '10.0.1.42',
    '2001:db8::8a2e:370:7334',
    'Vancouver, BC',
    '+1 604 555 0100',
    'Primary web server for the retainer',
    'wp_prod',
  ];
  for (const v of safeValues) {
    assert.strictEqual(secretReason(v), null, `safe value must not be redacted: ${v}`);
    assert.strictEqual(isFieldSafe({ type: 'STRING', value: v }), true, `STRING passes through: ${v}`);
  }

  // --- credential material in a STRING field must be caught (issue #4) ---
  const secretValues: Array<[string, string]> = [
    ['-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----', 'pem-private-key'],
    ['-----BEGIN RSA PRIVATE KEY-----', 'pem-private-key'],
    ['-----BEGIN CERTIFICATE-----', 'pem-block'],
    ['ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDl1nQ4Hk', 'ssh-key-blob'],
    ['ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123', 'github-token'],
    ['github_pat_11ABCDEFG0abcdefghijkl_MnOpQrStUvWxYz', 'github-pat'],
    ['glpat-AbCdEfGhIjKlMnOpQrSt', 'gitlab-token'],
    ['xoxb-123456789012-abcdefghijkl', 'slack-token'],
    ['sk-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789', 'openai-style-token'],
    ['AKIAIOSFODNN7EXAMPLE', 'aws-access-key-id'],
    ['AIzaSyD-1234567890abcdefghijklmnopqrstu', 'google-api-key'],
    ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N', 'jwt'],
    ['postgres://wp_user:s3cr3tp4ss@db.example.com:5432/wordpress', 'uri-with-credentials'],
    ['d41d8cd98f00b204e9800998ecf8427e0123456789abcdef', 'hex-blob'],
    ['aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZw==', 'base64-blob'],
  ];
  for (const [v, reason] of secretValues) {
    assert.strictEqual(secretReason(v), reason, `expected ${reason} for: ${v.slice(0, 32)}`);
    assert.strictEqual(isFieldSafe({ type: 'STRING', value: v }), false, `STRING with secret content redacted: ${reason}`);
  }

  // The content gate applies to every otherwise-safe field, not just STRING.
  assert.strictEqual(
    isFieldSafe({ purpose: 'USERNAME', value: '-----BEGIN OPENSSH PRIVATE KEY-----' }),
    false,
    'safe purpose does not exempt secret content',
  );
  assert.strictEqual(
    isFieldSafe({ type: 'URL', value: 'postgres://u:pw@db.example.com/x' }),
    false,
    'URL with embedded credentials is redacted',
  );

  // --- degenerate input ---
  assert.strictEqual(secretReason(undefined), null, 'missing value is not secret');
  assert.strictEqual(secretReason(null), null, 'null value is not secret');
  assert.strictEqual(secretReason(''), null, 'empty value is not secret');
  assert.strictEqual(secretReason('   '), null, 'whitespace value is not secret');
  assert.strictEqual(secretReason(42), null, 'non-string value is not secret');
  assert.strictEqual(isFieldSafe({ type: 'STRING', value: undefined }), true, 'STRING with no value stays safe');

  // A long human sentence is prose, not a blob - whitespace is the tell.
  assert.strictEqual(
    secretReason('This is the primary production web server for the client retainer'),
    null,
    'long prose is not treated as a blob',
  );
  // ...but a long undelimited token is, even with no recognised vendor prefix.
  // Which blob shape matches first is incidental - that it redacts is the point.
  assert.strictEqual(looksSecret('Zx9QwErTyUiOpAsDfGhJkLmNbVcXz0123456789'), true, 'unrecognised long token is redacted');
  assert.strictEqual(looksSecret('AbCdEf-GhIjKl_MnOpQr-StUvWx_Yz012345678'), true, 'long url-safe token is redacted');

  console.log('classify self-check passed');
}
