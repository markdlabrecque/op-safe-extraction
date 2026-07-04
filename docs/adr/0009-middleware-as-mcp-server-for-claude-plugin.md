# Middleware ships as an MCP server, called from within a Claude plugin

The agent runs as part of a Claude plugin for now, though the runtime may change later. We decided the middleware is an MCP server exposing exactly four read-only, vault-gated tools (list_vaults, list_items, search_items, get_item) — this makes the tool surface the literal set of things the agent can call, with no other path to 1Password, and keeps the middleware portable to other MCP-capable clients if the runtime changes.
