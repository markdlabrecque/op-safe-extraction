// Fail-closed field classification per ADR-0003 / CONTEXT.md.
// Gate on 1Password's own type/purpose, never on label text.

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
  console.assert(isFieldSafe({ type: 'STRING' }) === true, 'STRING should be safe');
  console.assert(isFieldSafe({ type: 'CONCEALED' }) === false, 'CONCEALED should be sensitive');
  console.assert(isFieldSafe({ type: 'SSHKEY' }) === false, 'SSHKEY should be sensitive');
  console.assert(isFieldSafe({ type: 'STRING', purpose: 'PASSWORD' }) === false, 'PASSWORD purpose is sensitive even as STRING');
  console.assert(isFieldSafe({ type: 'STRING', purpose: 'NOTES' }) === false, 'NOTES purpose is always sensitive');
  console.assert(isFieldSafe({ purpose: 'USERNAME' }) === true, 'USERNAME purpose is safe');
  console.assert(isFieldSafe({}) === false, 'unknown/missing type fails closed');
  console.log('classify self-check passed');
}
