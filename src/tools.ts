import { listVaultsRaw, listItemsRaw, getItemRaw } from './op.js';
import { getAllowlist, assertVaultAllowed } from './vaults.js';
import { isFieldSafe } from './classify.js';
import { logClassification } from './log.js';

export async function listVaults() {
  const vaults = await listVaultsRaw();
  const allowlist = getAllowlist();
  return vaults.map((v) => ({ id: v.id, name: v.name, allowed: allowlist.has(v.id) }));
}

export async function listItems(vaultId: string) {
  assertVaultAllowed(vaultId);
  const items = await listItemsRaw(vaultId);
  return items.map((i) => ({ id: i.id, title: i.title, tags: i.tags ?? [], category: i.category }));
}

export async function searchItems(vaultId: string, query?: string, tags?: string[]) {
  assertVaultAllowed(vaultId);
  let items = await listItemsRaw(vaultId);
  if (tags?.length) {
    items = items.filter((i) => tags.every((t) => (i.tags ?? []).includes(t)));
  }
  if (query) {
    const q = query.toLowerCase();
    items = items.filter((i) => i.title.toLowerCase().includes(q));
  }
  return items.map((i) => ({ id: i.id, title: i.title, tags: i.tags ?? [], category: i.category }));
}

export async function getItem(vaultId: string, itemId: string) {
  assertVaultAllowed(vaultId);
  const item = await getItemRaw(vaultId, itemId);
  const fields = (item.fields ?? [])
    .filter((f: any) => f.purpose !== 'NOTES') // notes dropped entirely, never even a redacted stub
    .map((f: any) => {
      const safe = isFieldSafe(f);
      logClassification({
        ts: new Date().toISOString(),
        vaultId,
        itemId: item.id,
        itemTitle: item.title,
        fieldLabel: f.label,
        fieldType: f.type,
        fieldPurpose: f.purpose,
        decision: safe ? 'safe' : 'redacted',
      });
      return { label: f.label, type: f.type, value: safe ? f.value : '[REDACTED]' };
    });
  return {
    id: item.id,
    title: item.title,
    vault: vaultId,
    category: item.category,
    tags: item.tags ?? [],
    fields,
  };
}
