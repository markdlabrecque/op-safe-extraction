# op-safe-extraction

An MCP server that lets an agent query 1Password item metadata — titles, tags,
usernames, URLs — without ever letting a sensitive value (password, passkey,
SSH key, notes) enter its context. See `CONTEXT.md` for the domain language
and `docs/adr/` for why each boundary is where it is.

## Setup

1. Install the [`op` CLI](https://developer.1password.com/docs/cli/) and
   authenticate (desktop session locally, or a service account token on a
   server — see ADR-0002).
2. Find the vault ID(s) you want reachable: `op vault list --format json`.
3. `npm install && npm run build`
4. Set `VAULT_ALLOWLIST` to a comma-separated list of those vault IDs. Any
   vault not on this list is visible by name but denied on item/field access
   (ADR-0006, ADR-0007).

## Running

The server speaks MCP over stdio. `.mcp.json` at the repo root registers it
for Claude Code / a Claude plugin — fill in `VAULT_ALLOWLIST` there, or set it
in your shell before launching.

```sh
VAULT_ALLOWLIST=<vault-id> npm start
```

## Tools

All four are read-only against 1Password (ADR-0005):

- `list_vaults` — every vault's id/name, plus whether it's allowlisted.
- `list_items(vaultId)` — titles, tags, categories in an allowlisted vault.
- `search_items(vaultId, query?, tags?)` — same, filtered by title text and/or tags.
- `get_item(vaultId, itemId)` — full item metadata. Sensitive fields (type
  `CONCEALED`/`SSHKEY`, purpose `PASSWORD`/`NOTES`) come back as
  `[REDACTED]`; everything else (username, URL, email, phone, address) is
  passed through as-is. The allowlist is fail-closed — any field type not
  explicitly known-safe is redacted (`src/classify.ts`). A Login item's
  website(s) live in `item.urls` rather than `item.fields`, and are returned
  in a separate `urls` array (label, href, primary), classified and logged the
  same way. Values that pass the type check are gated again on content, so
  credential material pasted into a plain text field (PEM blocks, SSH keys,
  vendor tokens, JWTs, URIs with embedded credentials, long high-entropy blobs)
  is redacted too. That second gate is a heuristic, not a hard boundary — see
  ADR-0010.

## Data disclosure report

Every `get_item` call appends a classification record (item, field, type,
decision, and for content-based redactions a reason — never the real value) to
`/tmp/op-safe-extraction/classification-log.jsonl`,
outside the agent's write scope. After a session, check whether anything
sensitive actually made it into the transcript:

```sh
npm run report -- /path/to/session-transcript.txt
```

This re-fetches the real value for each field logged as `redacted`, holds it
in memory only, and does an exact substring search against the transcript.
Any hit names the item/field to rotate. See ADR-0004 for the design and its
known limitation (exact-match only, won't catch a transformed/encoded copy
of a leaked value).

## Scope

The agent's own write access is confined to this project's `docs/` folder,
for producing reports — it has no path to write back to 1Password or to the
transcript/classification log it's checked against (ADR-0005, ADR-0008).
