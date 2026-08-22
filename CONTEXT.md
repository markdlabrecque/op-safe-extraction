# op-safe-extraction

An agent that queries 1Password item data through a middleware boundary, so the agent can reason about item structure without ever having secret values enter its context.

## Language

**Metadata**:
Item-level and field-level information about a 1Password entry that carries no secret content: item title, vault name, category, tags, timestamps, and per-field label/type. Always safe to pass to the agent.
_Avoid_: Attributes, properties

**Safe value**:
A field value whose content is not itself a credential, even though it lives alongside sensitive fields on the same item: username, URL, hostname, port. Passed through to the agent unredacted.
_Avoid_: Non-sensitive field, public field

**Sensitive value**:
A field value that is, or could be, a credential: password, passkey, SSH key. Also includes item notes (`notesPlain`) in this project, since free-text notes can contain unpredictable secret content. Never passed to the agent — enforced entirely by the middleware via a fail-closed allowlist on field `type`/`purpose` (no LLM-side instruction needed, since the allowlist is a hard boundary rather than a request for restraint).
_Avoid_: Secret, credential (too broad — notes are "sensitive" here without necessarily being a credential)

## Classification mechanism

Middleware classifies each field by 1Password's own `type`/`purpose` attributes, not by label text (labels are freeform and can't be trusted). Allowlisted as safe: `STRING`, `URL`, `EMAIL`, `PHONE`, `ADDRESS`, `purpose: USERNAME`. Everything else — including any field type not explicitly allowlisted — is treated as sensitive and redacted. `notesPlain` is dropped regardless of type.

**Content gate**:
A second check applied to any value the type/purpose gate would otherwise pass. Redacts structural credential markers (PEM blocks, SSH key blobs, known vendor token prefixes, JWTs, URIs with embedded credentials), multi-line blocks in single-line fields, and long undelimited high-entropy blobs. Safe-value shapes (URL, hostname, IP, port, email, `user@host`) are matched first and never treated as blobs. Exists because `type: STRING` records which widget the user chose, not what they pasted into it. Unlike the type allowlist, this is a heuristic with false negatives, not a hard boundary — see ADR-0010.
_Avoid_: Secret scanner (implies completeness this does not have)

**Classification log**:
A record the middleware appends to on every run: for each field it processes, the item id, field label, type/purpose, and its safe/redacted decision. Never contains the real value.
_Avoid_: Audit log (too generic)

**Vault allowlist**:
An explicit, middleware-enforced list of vault IDs the agent is permitted to query. Requests against any vault not on the list are rejected, fail closed. Vault names themselves are always visible (even for unlisted vaults) so the agent can suggest adding one — only item/field access within an unlisted vault is denied. Distinct from the field-level classification allowlist — this gates entire vaults, not fields within one.
_Avoid_: Vault filter, `--vault` flag (a CLI convenience, not the enforcement point)

**Data disclosure report**:
A post-run report, generated automatically at the end of every session, that tells you which sensitive values (if any) leaked into the agent's transcript so you know what to rotate. Built by re-fetching real values for every classification-log entry marked "redacted" (transiently, never persisted) and exact-substring-matching them against the transcript.
_Avoid_: Blast radius report (earlier, imprecise name for this)
