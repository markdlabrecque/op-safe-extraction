// Data disclosure report per ADR-0004: re-fetches real values transiently
// (never persisted) and exact-substring-matches them against a transcript.
import { readFileSync } from 'node:fs';
import { LOG_FILE } from '../src/log.js';
import { getItemRaw } from '../src/op.js';

const transcriptPath = process.argv[2];
if (!transcriptPath) {
  console.error('Usage: npm run report -- <transcript-file>');
  process.exit(1);
}

const transcript = readFileSync(transcriptPath, 'utf8');
const records = readFileSync(LOG_FILE, 'utf8')
  .trim()
  .split('\n')
  .filter(Boolean)
  .map((l) => JSON.parse(l))
  .filter((r) => r.decision === 'redacted');

const seen = new Set<string>();
const leaks: { itemTitle: string; fieldLabel: string; itemId: string }[] = [];

for (const r of records) {
  const key = `${r.vaultId}:${r.itemId}:${r.fieldLabel}`;
  if (seen.has(key)) continue;
  seen.add(key);

  const item = await getItemRaw(r.vaultId, r.itemId);
  const field = (item.fields ?? []).find((f: any) => f.label === r.fieldLabel);
  if (!field?.value || !transcript.includes(field.value)) continue;

  leaks.push({ itemTitle: r.itemTitle, fieldLabel: r.fieldLabel, itemId: r.itemId });
}

if (leaks.length === 0) {
  console.log('No disclosures found. Transcript is clean.');
} else {
  console.log(`DISCLOSURE: ${leaks.length} sensitive value(s) found in transcript. Rotate these:`);
  for (const l of leaks) console.log(`  - "${l.itemTitle}" / ${l.fieldLabel} (item ${l.itemId})`);
  process.exitCode = 1;
}
