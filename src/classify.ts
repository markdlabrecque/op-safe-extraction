// Fail-closed field classification per ADR-0003 / CONTEXT.md.
// Gate on 1Password's own type/purpose, never on label text.

import assert from 'node:assert/strict';
const SAFE_TYPES = new Set(['STRING', 'URL', 'EMAIL', 'PHONE', 'ADDRESS']);
const SAFE_PURPOSES = new Set(['USERNAME']);
const ALWAYS_SENSITIVE_PURPOSES = new Set(['NOTES', 'PASSWORD']);

export interface OpField {
  type?: string;
  purpose?: string;
}

export function isFieldSafe(field: OpField): boolean {
  if (field.purpose && ALWAYS_SENSITIVE_PURPOSES.has(field.purpose)) return false;
  if (field.purpose && SAFE_PURPOSES.has(field.purpose)) return true;
  return !!field.type && SAFE_TYPES.has(field.type);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  assert.strictEqual(isFieldSafe({ type: 'STRING' }), true, 'STRING should be safe');
  assert.strictEqual(isFieldSafe({ type: 'CONCEALED' }), false, 'CONCEALED should be sensitive');
  assert.strictEqual(isFieldSafe({ type: 'SSHKEY' }), false, 'SSHKEY should be sensitive');
  assert.strictEqual(isFieldSafe({ type: 'STRING', purpose: 'PASSWORD' }), false, 'PASSWORD purpose is sensitive even as STRING');
  assert.strictEqual(isFieldSafe({ type: 'STRING', purpose: 'NOTES' }), false, 'NOTES purpose is always sensitive');
  assert.strictEqual(isFieldSafe({ purpose: 'USERNAME' }), true, 'USERNAME purpose is safe');
  assert.strictEqual(isFieldSafe({}), false, 'unknown/missing type fails closed');

  // Fail-closed: anything not explicitly allowlisted is sensitive.
  assert.strictEqual(isFieldSafe({ type: 'OTP' }), false, 'unrecognised type fails closed');
  assert.strictEqual(isFieldSafe({ type: 'CREDIT_CARD_NUMBER' }), false, 'card number fails closed');
  assert.strictEqual(isFieldSafe({ type: 'string' }), false, 'type match is case-sensitive, lowercase fails closed');
  assert.strictEqual(isFieldSafe({ purpose: 'username' }), false, 'purpose match is case-sensitive, lowercase fails closed');

  console.log('classify self-check passed');
}
