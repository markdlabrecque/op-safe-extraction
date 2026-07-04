# Agent is read-only against 1Password; write access is scoped to producing the report only

The agent has general write-tool access for producing its output, but we explicitly do not want it to write anything back to 1Password. We decided the middleware only exposes read operations against 1Password (no update/create/delete on items or fields), regardless of what other file-writing tools the agent has. The agent's write access is scoped entirely to authoring its report — it has no path, direct or indirect, to mutate 1Password data.
