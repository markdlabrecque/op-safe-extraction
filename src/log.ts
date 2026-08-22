// Classification log per ADR-0004/0008: lives outside the agent's write
// scope (docs/ only), never stores real field values.
import { appendFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const LOG_DIR = '/tmp/op-safe-extraction';
export const LOG_FILE = join(LOG_DIR, 'classification-log.jsonl');

export interface ClassificationRecord {
  ts: string;
  vaultId: string;
  itemId: string;
  itemTitle: string;
  fieldLabel: string;
  fieldType?: string;
  fieldPurpose?: string;
  decision: 'safe' | 'redacted';
  // Why the value was redacted, when a content heuristic caught it rather than
  // the type/purpose allowlist (ADR-0010). Never contains the value itself.
  reason?: string;
}

export function logClassification(record: ClassificationRecord): void {
  mkdirSync(LOG_DIR, { recursive: true });
  appendFileSync(LOG_FILE, JSON.stringify(record) + '\n');
}
