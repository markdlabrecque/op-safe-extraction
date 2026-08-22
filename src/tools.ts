import assert from 'node:assert/strict';
import { listVaultsRaw, listItemsRaw, getItemRaw } from './op.js';
import { getAllowlist, assertVaultAllowed } from './vaults.js';
import { isFieldSafe, secretReason } from './classify.js';
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

export interface OpUrl {
  label?: string;
  href?: string;
  primary?: boolean;
}

export interface MappedUrl {
  label: string;
  href: string;
  primary: boolean;
}

// 1Password returns a Login item's website(s) in `item.urls`, not `item.fields`,
// so they were previously dropped entirely rather than classified. URLs and
// hostnames are safe values per CONTEXT.md; still routed through isFieldSafe so
// they redact automatically if URL ever leaves the safe allowlist. See issue #1.
export function mapUrls(urls: unknown): MappedUrl[] {
  if (!Array.isArray(urls)) return [];
  return urls
    .filter((u): u is OpUrl & { href: string } => !!u && typeof u === 'object' && typeof (u as OpUrl).href === 'string')
    .map((u) => ({
      // `label` is whatever op emitted; coerce anything non-string to the
      // default so MappedUrl.label is a string at runtime, not just in types.
      label: typeof u.label === 'string' && u.label !== '' ? u.label : 'website',
      href: isFieldSafe({ type: 'URL', value: u.href }) ? u.href : '[REDACTED]',
      primary: u.primary === true,
    }));
}

export async function getItem(vaultId: string, itemId: string) {
  assertVaultAllowed(vaultId);
  const item = await getItemRaw(vaultId, itemId);
  const fields = (item.fields ?? [])
    .filter((f: any) => f.purpose !== 'NOTES') // notes dropped entirely, never even a redacted stub
    .map((f: any) => {
      const safe = isFieldSafe(f);
      const reason = safe ? undefined : (secretReason(f.value) ?? undefined);
      logClassification({
        ts: new Date().toISOString(),
        vaultId,
        itemId: item.id,
        itemTitle: item.title,
        fieldLabel: f.label,
        fieldType: f.type,
        fieldPurpose: f.purpose,
        decision: safe ? 'safe' : 'redacted',
        reason,
      });
      return { label: f.label, type: f.type, value: safe ? f.value : '[REDACTED]' };
    });

  const urls = mapUrls(item.urls);
  for (const u of urls) {
    logClassification({
      ts: new Date().toISOString(),
      vaultId,
      itemId: item.id,
      itemTitle: item.title,
      fieldLabel: u.label,
      fieldType: 'URL',
      decision: u.href === '[REDACTED]' ? 'redacted' : 'safe',
      reason: u.href === '[REDACTED]' ? 'url-content-gate' : undefined,
    });
  }

  return {
    id: item.id,
    title: item.title,
    vault: vaultId,
    category: item.category,
    tags: item.tags ?? [],
    fields,
    urls,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  assert.deepStrictEqual(
    mapUrls([{ label: 'website', href: 'https://prod.example.com', primary: true }]),
    [{ label: 'website', href: 'https://prod.example.com', primary: true }],
    'a safe url is mapped through unchanged',
  );

  const unlabelled = mapUrls([{ href: 'ssh://box.example.com' }]);
  assert.strictEqual(unlabelled[0].label, 'website', 'missing label defaults to website');
  assert.strictEqual(unlabelled[0].primary, false, 'missing primary defaults to false');

  // op's JSON is not schema-guaranteed, so label must be coerced, not trusted.
  assert.strictEqual(typeof mapUrls([{ label: 42, href: 'https://a.example' }])[0].label, 'string', 'numeric label coerced to string');
  assert.strictEqual(mapUrls([{ label: 42, href: 'https://a.example' }])[0].label, 'website', 'numeric label falls back to default');
  assert.strictEqual(mapUrls([{ label: null, href: 'https://a.example' }])[0].label, 'website', 'null label falls back to default');
  assert.strictEqual(mapUrls([{ label: '', href: 'https://a.example' }])[0].label, 'website', 'empty label falls back to default');
  assert.strictEqual(mapUrls([{ primary: 'yes', href: 'https://a.example' }])[0].primary, false, 'truthy non-boolean primary is not treated as true');

  assert.strictEqual(mapUrls(undefined).length, 0, 'missing urls yields empty list');
  assert.strictEqual(mapUrls([]).length, 0, 'empty urls yields empty list');
  assert.strictEqual(mapUrls('nope').length, 0, 'non-array urls yields empty list');
  assert.strictEqual(mapUrls([{ label: 'broken' }]).length, 0, 'entry without href is skipped');
  assert.strictEqual(mapUrls([null, undefined, { href: 'https://a.example' }]).length, 1, 'null and undefined entries skipped');
  assert.strictEqual(mapUrls([{ href: 'https://a.example' }, { href: 'https://b.example' }]).length, 2, 'multiple urls mapped');

  console.log('tools self-check passed');
}
