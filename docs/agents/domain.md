# Domain docs

Single-context: one `GLOSSARY.md` at the repo root and ADRs in `docs/adr/`.

Before exploring, read `GLOSSARY.md` and the ADRs that touch the area you are about to work in.

If they don't exist, **proceed silently**: don't flag their absence or create them upfront. `/domain-modeling` creates them lazily when a term or decision gets resolved.

- **Use the glossary's vocabulary** when naming a domain concept (issue titles, proposals, hypotheses, test names). Don't drift to synonyms it avoids. A concept missing from it is either invented language (reconsider) or a real gap (note it for `/domain-modeling`).
- **Flag ADR conflicts** explicitly instead of overriding them: _Contradicts ADR-0007 (…), but worth reopening because…_
