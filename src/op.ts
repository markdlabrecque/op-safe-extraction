// Thin wrapper around the `op` CLI. execFile, never a shell, to avoid injection via ids/queries.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

async function opJson<T>(args: string[]): Promise<T> {
  const { stdout } = await run('op', [...args, '--format', 'json']);
  return JSON.parse(stdout) as T;
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
