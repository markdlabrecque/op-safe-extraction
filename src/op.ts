// Thin wrapper around the `op` CLI. execFile, never a shell, to avoid injection via ids/queries.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

// Node's execFile defaults to a 1MB stdout cap, which `op item list` exceeds on
// large vaults (~1,900+ items). The CLI has no offset/limit flags to page with,
// so raise the ceiling instead. See issue #2.
const MAX_BUFFER = 256 * 1024 * 1024;

// Distinguishes "vault too large to read" from a denied vault or an
// unauthenticated `op`, which are otherwise indistinguishable at the MCP boundary.
export class OpOutputTooLargeError extends Error {
  constructor(args: string[]) {
    super(
      `op output exceeded ${MAX_BUFFER} bytes for \`op ${args.join(' ')}\`. ` +
        'The vault is too large to read in one call.',
    );
    this.name = 'OpOutputTooLargeError';
  }
}

// Node signals this via `code` on newer releases and via message text on older
// ones. The message match is deliberately narrow: a loose /maxBuffer/ test would
// swallow unrelated CLI failures that merely mention the word, masking the real
// error behind OpOutputTooLargeError.
const MAX_BUFFER_MESSAGE = /\b(?:stdout|stderr) maxBuffer length exceeded\b/;

export function isMaxBufferError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const e = err as { code?: unknown; message?: unknown };
  if (e.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') return true;
  return typeof e.message === 'string' && MAX_BUFFER_MESSAGE.test(e.message);
}

async function opJson<T>(args: string[]): Promise<T> {
  try {
    const { stdout } = await run('op', [...args, '--format', 'json'], { maxBuffer: MAX_BUFFER });
    return JSON.parse(stdout) as T;
  } catch (err) {
    if (isMaxBufferError(err)) throw new OpOutputTooLargeError(args);
    throw err;
  }
}

export function listVaultsRaw() {
  return opJson<any[]>(['vault', 'list']);
}

export function listItemsRaw(vaultId: string) {
  return opJson<any[]>(['item', 'list', '--vault', vaultId]);
}

export function getItemRaw(vaultId: string, itemId: string) {
  return opJson<any>(['item', 'get', itemId, '--vault', vaultId]);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  assert.strictEqual(isMaxBufferError({ code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' }), true, 'code form detected');
  assert.strictEqual(isMaxBufferError({ message: 'stdout maxBuffer length exceeded' }), true, 'stdout message form detected');
  assert.strictEqual(isMaxBufferError({ message: 'stderr maxBuffer length exceeded' }), true, 'stderr message form detected');
  assert.strictEqual(isMaxBufferError({ message: 'command not found: op' }), false, 'unrelated error not misread');
  // A failure that merely mentions maxBuffer must keep its own identity, or
  // opJson would report it as OpOutputTooLargeError and hide the real cause.
  assert.strictEqual(isMaxBufferError({ message: 'unrelated failure: maxBuffer' }), false, 'incidental mention not misread');
  assert.strictEqual(isMaxBufferError({ message: 'invalid maxBuffer option' }), false, 'option error not misread');
  assert.strictEqual(isMaxBufferError(null), false, 'null is not a maxBuffer error');
  assert.strictEqual(isMaxBufferError(undefined), false, 'undefined is not a maxBuffer error');
  assert.strictEqual(isMaxBufferError('stdout maxBuffer length exceeded'), false, 'a bare string is not an error object');
  assert.strictEqual(isMaxBufferError({ message: 42 }), false, 'non-string message is not a maxBuffer error');
  assert.strictEqual(new OpOutputTooLargeError(['item', 'list']).name, 'OpOutputTooLargeError', 'error is named');

  console.log('op self-check passed');
}
