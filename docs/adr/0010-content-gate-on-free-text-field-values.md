# Gate free-text field values on content as well as type, and say plainly that this part is a heuristic

ADR-0003 claims the type/purpose allowlist leaves "no gap." That was wrong in one specific way: `STRING` is on the safe list, and a 1Password field `type` records which widget the user picked, not what they typed into it. A private key, API token, or `postgres://user:password@host/db` connection string pasted into an ordinary text field is a `STRING`, so it was classified safe and passed through in full. The disclosure report could not catch it either, since that only re-checks values logged as `redacted`.

Dropping `STRING` from the allowlist would have closed the gap and also redacted most legitimate metadata, including the hostnames and ports that CONTEXT.md names as safe values — the project's whole reason to exist. Per-vault label allowlisting was rejected as too much configuration for a tool this small.

We decided to keep `STRING` and add a second gate on the value itself: structural markers (PEM blocks, SSH key blobs, known vendor token prefixes, JWTs, URIs with embedded credentials), any multi-line block in a single-line field, and long undelimited high-entropy blobs. Values matching this project's safe-value vocabulary — URL, hostname, IP, port, email, `user@host` — are checked first and never treated as blobs. The gate applies to every otherwise-safe field, not just `STRING`, so a safe `purpose` cannot exempt secret content.

The important part is what this is not. The type/purpose allowlist is a hard boundary: it depends on nothing but 1Password's own attributes. The content gate is a **heuristic**, and heuristics have false negatives — a novel token format with no recognised prefix, below the entropy threshold, sitting in a `STRING` field, still passes. Recording that here rather than restating ADR-0003's "no gap," because the gap is narrower now but not closed. Anything genuinely secret still belongs in a `CONCEALED` field, where the hard boundary applies.

Redaction reasons are written to the classification log (never the value) so the disclosure report can distinguish a type-based redaction from a content-based one.
