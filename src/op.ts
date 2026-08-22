// Thin wrapper around the `op` CLI. execFile, never a shell, to avoid injection via ids/queries.
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

export function isMaxBufferError(err: unknown): boolean {
  const e = err as { code?: string; message?: string } | null;
  return !!e && (e.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' || /maxBuffer/i.test(e.message ?? ''));
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
  console.assert(isMaxBufferError({ code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' }) === true, 'code form detected');
  console.assert(isMaxBufferError({ message: 'stdout maxBuffer length exceeded' }) === true, 'message form detected');
  console.assert(isMaxBufferError({ message: 'command not found: op' }) === false, 'unrelated error not misread');
  console.assert(isMaxBufferError(null) === false, 'null is not a maxBuffer error');
  console.assert(new OpOutputTooLargeError(['item', 'list']).name === 'OpOutputTooLargeError', 'error is named');
  console.log('op self-check passed');
}
