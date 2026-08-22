// Vault allowlist per ADR-0006/0007: fail closed on item/field access,
// but vault names stay visible so the agent can suggest adding one.

import assert from 'node:assert/strict';
export function getAllowlist(): Set<string> {
  const raw = process.env.VAULT_ALLOWLIST ?? '';
  return new Set(raw.split(',').map((s) => s.trim()).filter(Boolean));
}

export function assertVaultAllowed(vaultId: string): void {
  if (!getAllowlist().has(vaultId)) {
    throw new Error(
      `Vault ${vaultId} is not on the allowlist. Ask the user to add it to VAULT_ALLOWLIST if this vault should be reachable.`,
    );
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const original = process.env.VAULT_ALLOWLIST;
  const withAllowlist = (raw: string | undefined, fn: () => void) => {
    if (raw === undefined) delete process.env.VAULT_ALLOWLIST;
    else process.env.VAULT_ALLOWLIST = raw;
    fn();
  };

  try {
    withAllowlist('vault-a,vault-b', () => {
      assert.doesNotThrow(() => assertVaultAllowed('vault-a'), 'allowlisted vault passes');
      assert.doesNotThrow(() => assertVaultAllowed('vault-b'), 'second allowlisted vault passes');
      assert.throws(() => assertVaultAllowed('vault-c'), /not on the allowlist/, 'unlisted vault is denied');
      assert.strictEqual(getAllowlist().size, 2, 'two entries parsed');
    });

    // Fail closed when unconfigured - the boundary must not default to open.
    withAllowlist(undefined, () => {
      assert.strictEqual(getAllowlist().size, 0, 'unset env yields empty allowlist');
      assert.throws(() => assertVaultAllowed('vault-a'), /not on the allowlist/, 'unset env denies everything');
    });
    withAllowlist('', () => {
      assert.throws(() => assertVaultAllowed('vault-a'), /not on the allowlist/, 'empty env denies everything');
    });
    withAllowlist('   ', () => {
      assert.throws(() => assertVaultAllowed('vault-a'), /not on the allowlist/, 'whitespace-only env denies everything');
    });

    withAllowlist(' vault-a , vault-b ', () => {
      assert.doesNotThrow(() => assertVaultAllowed('vault-a'), 'surrounding whitespace is trimmed');
      assert.doesNotThrow(() => assertVaultAllowed('vault-b'), 'whitespace after comma is trimmed');
    });
    withAllowlist('vault-a,,vault-b,', () => {
      assert.strictEqual(getAllowlist().size, 2, 'empty entries are dropped');
      assert.throws(() => assertVaultAllowed(''), /not on the allowlist/, 'empty vault id is never allowed');
    });

    // Matching is exact - no prefix or substring escape.
    withAllowlist('vault-a', () => {
      assert.throws(() => assertVaultAllowed('vault-a-extra'), /not on the allowlist/, 'prefix does not match');
      assert.throws(() => assertVaultAllowed('ault-a'), /not on the allowlist/, 'substring does not match');
      assert.throws(() => assertVaultAllowed('VAULT-A'), /not on the allowlist/, 'match is case-sensitive');
    });

    withAllowlist('vault-a', () => {
      assert.throws(() => assertVaultAllowed('vault-c'), /VAULT_ALLOWLIST/, 'error names the env var to fix');
    });
  } finally {
    if (original === undefined) delete process.env.VAULT_ALLOWLIST;
    else process.env.VAULT_ALLOWLIST = original;
  }

  console.log('vaults self-check passed');
}
