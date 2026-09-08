# Domain Docs

How engineering skills and autonomous agents consume this repository's domain documentation when exploring the codebase.

---

## 1. Before Exploring, Read These

- **`CONTEXT.md`** at the repo root: Defines core domain concepts, glossary, and ubiquitous language.
- **`CONTEXT-MAP.md`** at the repo root (if present): Points to context-scoped `CONTEXT.md` files in multi-context layouts.
- **`docs/adr/`**: Read Architecture Decision Records touching the area you are about to work in.

> **Note on Missing Files**: If any of these files do not yet exist, **proceed silently**. Do not flag their absence or suggest creating them upfront. The `/domain-modeling` skill creates them lazily as terms or architectural decisions are formally resolved.

---

## 2. File Structure

Single-context repository (current baseline for AgentSec Lab):

```text
/
├── CONTEXT.md
├── docs/
│   ├── adr/
│   │   ├── ADR-001-core-language-and-runtime.md
│   │   ├── ADR-002-mvp-event-persistence.md
│   │   └── ADR-003-mvp-isolation-and-no-egress.md
│   └── agents/
└── src/
```

---

## 3. Use the Glossary's Vocabulary

- When naming a domain concept (in issue titles, PR summaries, refactor proposals, or test fixtures), use the exact terminology established in `CONTEXT.md` and `PROJECT_BRIEF.md`.
- Do not drift to synonyms that the project explicitly avoids (e.g. use "Tool Gateway", "LabHttpSinkAdapter", "Deterministic Mock Agent").
- If a concept is missing from the glossary, consider whether you are inventing unofficial terminology or if there is a genuine gap to record with `/domain-modeling`.

---

## 4. Flag ADR Conflicts

If an implementation proposal or architecture change contradicts an existing ADR, surface the conflict explicitly rather than silently overriding it:

> *Example: Contradicts ADR-003 (in-process socket-free isolation), but worth reopening because...*
