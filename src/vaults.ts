// Vault allowlist per ADR-0006/0007: fail closed on item/field access,
// but vault names stay visible so the agent can suggest adding one.

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
