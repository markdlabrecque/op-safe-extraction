# Classify sensitivity by field type/purpose with a fail-closed allowlist; no LLM-side fallback instruction

We initially planned a fallback LLM instruction to avoid reading values that "look sensitive," on top of middleware enforcement. We decided against it: since the middleware classifies every field by 1Password's own `type`/`purpose` attributes (not label text) and fails closed — any field type not explicitly allowlisted as safe is redacted — there is no gap for a prompt-level fallback to cover. Adding one would only create the false impression that the boundary depends partly on the LLM's behavior, when it doesn't.

**Amended by ADR-0010.** The "no gap" claim above does not hold for `STRING`, which is allowlisted by type but unbounded in content. A content gate now covers the realistic cases; it is a heuristic, not a hard boundary. The conclusion about LLM-side fallback is unchanged — the fix was more middleware, not a prompt.
