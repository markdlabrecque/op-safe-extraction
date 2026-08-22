// Item category denylist per ADR-0011: narrows which kinds of items this
// integration will touch at all, independent of the vault allowlist
// (ADR-0006/0007) and of field sensitivity classification (ADR-0003).

import assert from 'node:assert/strict';

export const ENV_VAR = 'ITEM_CATEGORY_DENYLIST';

// 1Password's own category identifiers, as emitted by `op --format json`.
// Used only to warn about denylist entries that match nothing - never to
// restrict what may be denied.
const KNOWN_CATEGORIES = new Set([
  'API_CREDENTIAL', 'BANK_ACCOUNT', 'CREDIT_CARD', 'CRYPTO_WALLET', 'CUSTOM',
  'DATABASE', 'DOCUMENT', 'DRIVER_LICENSE', 'EMAIL_ACCOUNT', 'IDENTITY',
  'LOGIN', 'MEDICAL_RECORD', 'MEMBERSHIP', 'OUTDOOR_LICENSE', 'PASSPORT',
  'PASSWORD', 'REWARD_PROGRAM', 'SECURE_NOTE', 'SERVER', 'SOCIAL_SECURITY_NUMBER',
  'SOFTWARE_LICENSE', 'SSH_KEY', 'WIRELESS_ROUTER',
]);

/**
 * Fold a category to a single comparable form.
 *
 * Unlike vault ids, which are opaque tokens compared exactly, categories are
 * human-typed enum names. `op --format json` emits `SSH_KEY` while the 1Password
 * UI shows "SSH Key", so both must land on the same key. A denylist that fails
 * to match denies nothing, so leniency here is the safe direction.
 */
export function normalizeCategory(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  return raw.trim().toUpperCase().replace(/[\s-]+/g, '_');
}

export function getCategoryDenylist(): Set<string> {
  const raw = process.env[ENV_VAR] ?? '';
  return new Set(raw.split(',').map(normalizeCategory).filter(Boolean));
}

export function isCategoryDenied(category: unknown): boolean {
  const normalized = normalizeCategory(category);
  if (!normalized) return false; // an item with no category cannot match an entry
  return getCategoryDenylist().has(normalized);
}

export function assertCategoryAllowed(category: unknown): void {
  if (isCategoryDenied(category)) {
    throw new Error(
      `Item category ${normalizeCategory(category)} is denied by ${ENV_VAR}. ` +
        `Ask the user to remove it from ${ENV_VAR} if this category should be reachable.`,
    );
  }
}

/**
 * Entries matching no known category are almost certainly typos, and a typo in a
 * denylist silently denies nothing. Warn on stderr - never stdout, which carries
 * the MCP protocol.
 */
export function warnUnknownDenylistEntries(write: (msg: string) => void = (m) => process.stderr.write(m)): string[] {
  const unknown = [...getCategoryDenylist()].filter((c) => !KNOWN_CATEGORIES.has(c));
  if (unknown.length) {
    write(
      `[op-safe-extraction] warning: ${ENV_VAR} contains ${unknown.length} ` +
        `unrecognised categor${unknown.length === 1 ? 'y' : 'ies'}: ${unknown.join(', ')}. ` +
        'These deny nothing. Check for typos against 1Password\'s category names.\n',
    );
  }
  return unknown;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const original = process.env[ENV_VAR];
  const withDenylist = (raw: string | undefined, fn: () => void) => {
    if (raw === undefined) delete process.env[ENV_VAR];
    else process.env[ENV_VAR] = raw;
    fn();
  };

  try {
    // Unset, empty, and whitespace-only all deny nothing - current behaviour
    // is preserved for anyone who never sets the variable.
    for (const raw of [undefined, '', '   ', ',', ' , , ']) {
      withDenylist(raw, () => {
        assert.strictEqual(getCategoryDenylist().size, 0, `no entries parsed from ${JSON.stringify(raw)}`);
        assert.strictEqual(isCategoryDenied('DATABASE'), false, `nothing denied for ${JSON.stringify(raw)}`);
        assert.doesNotThrow(() => assertCategoryAllowed('DATABASE'), 'no denylist means no denial');
      });
    }

    withDenylist('DATABASE,SSH_KEY', () => {
      assert.strictEqual(isCategoryDenied('DATABASE'), true, 'listed category is denied');
      assert.strictEqual(isCategoryDenied('SSH_KEY'), true, 'second listed category is denied');
      assert.strictEqual(isCategoryDenied('LOGIN'), false, 'unlisted category passes');
      assert.throws(() => assertCategoryAllowed('DATABASE'), /denied by ITEM_CATEGORY_DENYLIST/, 'error names the env var');
      assert.throws(() => assertCategoryAllowed('DATABASE'), /DATABASE/, 'error names the category');
      assert.doesNotThrow(() => assertCategoryAllowed('LOGIN'), 'unlisted category does not throw');
    });

    // A denylist that fails to match denies nothing, so matching is lenient by
    // design - the opposite of the vault allowlist.
    withDenylist(' database , ssh key ', () => {
      assert.strictEqual(isCategoryDenied('DATABASE'), true, 'lowercase entry still denies');
      assert.strictEqual(isCategoryDenied('SSH_KEY'), true, 'spaced entry matches underscore form');
    });
    withDenylist('SSH_KEY', () => {
      assert.strictEqual(isCategoryDenied('SSH Key'), true, 'spaced item category matches underscore entry');
      assert.strictEqual(isCategoryDenied('ssh-key'), true, 'hyphen form matches too');
    });

    // Items with no usable category must not accidentally match an entry.
    withDenylist('DATABASE', () => {
      assert.strictEqual(isCategoryDenied(undefined), false, 'missing category is not denied');
      assert.strictEqual(isCategoryDenied(null), false, 'null category is not denied');
      assert.strictEqual(isCategoryDenied(''), false, 'empty category is not denied');
      assert.strictEqual(isCategoryDenied(42), false, 'non-string category is not denied');
      assert.doesNotThrow(() => assertCategoryAllowed(undefined), 'missing category does not throw');
    });

    assert.strictEqual(normalizeCategory('  Secure Note '), 'SECURE_NOTE', 'trims, uppercases, and joins words');
    assert.strictEqual(normalizeCategory(undefined), '', 'non-string normalizes to empty');

    // Typos deny nothing, so they must be visible rather than silent.
    withDenylist('DATABASE,DATBASE', () => {
      const seen: string[] = [];
      const unknown = warnUnknownDenylistEntries((m) => seen.push(m));
      assert.deepStrictEqual(unknown, ['DATBASE'], 'only the unrecognised entry is reported');
      assert.strictEqual(seen.length, 1, 'a warning was written');
      assert.ok(/DATBASE/.test(seen[0]), 'warning names the bad entry');
      assert.ok(!/DATABASE,/.test(seen[0]), 'warning does not flag the valid entry');
      assert.strictEqual(isCategoryDenied('DATABASE'), true, 'a bad entry does not break the good ones');
    });
    withDenylist('DATABASE,SSH_KEY', () => {
      const seen: string[] = [];
      assert.deepStrictEqual(warnUnknownDenylistEntries((m) => seen.push(m)), [], 'no unknown entries');
      assert.strictEqual(seen.length, 0, 'nothing written when all entries are known');
    });
  } finally {
    if (original === undefined) delete process.env[ENV_VAR];
    else process.env[ENV_VAR] = original;
  }

  console.log('categories self-check passed');
}
