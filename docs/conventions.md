# Conventions

> **What this file is.** The coding conventions of this project, distilled so
> that any tool or contributor can follow them — including ones that do NOT run
> Claude Code and therefore never see `.claude/rules/`. If you are an AI or an
> editor working in this repo (Xcode, a sandboxed subdir, a different
> assistant), **read this file and follow it** before writing or changing code.
>
> **Source of truth.** The canonical, always-current version of these rules
> lives in `.claude/rules/` (`code-quality.md`, `security.md`, `workflow.md`,
> `ai-collaboration.md`), which Claude Code loads automatically. This file is a
> portable mirror of those rules for everyone else. If the two ever disagree,
> `.claude/rules/` wins — and the mirror should be re-synced (see the footer).
>
> **What this file is NOT.** Not the product contract — that is `backend.md`
> (API), `ui.md` (visual), and `user-stories.md` (behavior). This file is about
> *how to write the code*, not *what the code does*.

## Code quality

- **Match existing conventions first.** Before writing new code in an area,
  read 2-3 sibling files and mimic their naming, error handling, structure,
  imports, and test layout. Consistency beats locally-"better" patterns.
  Exception: do not replicate a genuinely harmful pattern (security flaw,
  broken type safety, a documented anti-pattern) — surface it instead.
- **No speculative code.** Only what the requested functionality needs. Nothing
  "just in case".
- **Strict typing.** Type everything the language allows; lean on the type
  system. Avoid `any`, `unwrap()`, `!.` and equivalents in production paths.
- **Explicit error handling.** Every failed operation is logged or returned
  with enough context to diagnose. No silently swallowed errors.
- **Structured logging.** Levels (debug/info/warn/error) with context. Log
  decisions and external-call boundaries, not just errors.
- **Reusable, zero hardcoding.** Literals go to named constants or central
  config; shared logic is abstracted, not duplicated. No magic numbers/strings
  (`86400` → `SECONDS_PER_DAY`, `"admin"` → a named constant). A literal used
  once in obvious local context (`if status == 200`) may stay raw.
- **Comments explain the why, never the what.** Well-named identifiers cover
  the what. All comments in English.
- **Flat over nested.** Validate and early-return at the top; keep the happy
  path flat. More than ~2 levels of nesting → refactor into named helpers.
- **Tests with explicit intent.** Specify the cases and expected behavior, not
  just "write tests" — cover more than the happy path.
- **Verify external references.** Only use libraries/APIs that verifiably exist
  and are maintained. If unsure of a signature or version, say so.
- **Match logic to the domain.** Pick the data structure/algorithm that maps to
  the real use case (a FIFO queue for a waiting line, not a stack). Ask if the
  requirement is ambiguous.
- **Scalability awareness.** State the complexity of non-trivial algorithms;
  watch for O(n²) where O(n log n) is possible, N+1 queries, missing indexes,
  sync calls that should be async.
- **Don't hand-fix what a linter does.** Formatting, import order, and naming
  are the linter's job — run it, don't burn effort correcting style by hand.

## Security

> Review with at least the rigor of human-written code, especially anything touching I/O, auth, or deps.

- **Validate at every boundary.** All external input (user, API, file, env var)
  is validated and sanitized before use.
- **No injection.** Never build SQL, shell, or HTML by string concatenation —
  use parameterized queries, escape APIs, or safe templates.
- **Least privilege.** Each component gets only the access it needs.
- **Don't leak internals in errors.** User-facing errors stay generic; detail
  goes to server-side logs.
- **Constant-time comparison** for tokens/hashes/secrets (`hmac.compare_digest`,
  `crypto.timingSafeEqual`), never `==`.
- **No homegrown crypto.** Use established libraries.
- **Validate before deserializing** untrusted data; prefer data-only formats.
- **Secrets only in memory or a manager.** Never log, serialize, or put them in
  URLs. The repo blocks reads of `.env`/`secrets/`/`credentials/`.
- **Don't trust the client.** All security validation happens server-side;
  frontend checks are UX only.
- **Pin and audit dependencies.** Lockfiles + exact versions; run the
  ecosystem audit (`npm audit`, `pip-audit`, `cargo audit`, `govulncheck`).
- **Uploaded files:** validate by magic bytes, not extension; no execute bit on
  upload dirs.

## Workflow & git

- **One feature/fix per branch** (`feature/<name>`, `fix/<name>`); merge to
  `main` only when complete and verified. (In this repo a hook blocks direct
  pushes to main and all force pushes; other tools should follow the same
  discipline by hand.)
- **Atomic commits:** one logical change each; the message covers what and why.
  Never `--amend` without explicit confirmation. **Never add a
  `Co-Authored-By` / `Signed-off-by` trailer** unless explicitly requested.
- **Work in small chunks** — one function/bug/feature at a time.
- **A task is done** only when it compiles, passes tests (if any), and the
  change is recorded in `CHANGELOG.md` (Keep a Changelog 1.1.0 + SemVer).
- **Understand before implementing.** Ask when requirements are ambiguous;
  don't write code on a guess.
- **Keep the contract docs true.** If a change alters a contract, update the
  matching file in `docs/` (`backend.md` / `ui.md` / `user-stories.md`).

## Collaboration & output

- **Language:** talk to the user in their working language; keep everything
  *inside* the codebase in English (identifiers, comments, commit messages,
  logs, docs). In this project the user works in Castilian Spanish.
- **No emojis** in code, commits, messages, or docs unless strictly necessary.
- **Cite sources** (markdown links) when an answer relies on external docs or
  articles.
- **Ask for decisions with a multiple-choice prompt, not prose.** When you need
  the user to choose or decide, present 2-4 concrete options via the
  tool/UI for that (`AskUserQuestion` in Claude Code), not a typed-answer
  question. Plain prose only for genuinely open-ended input (a description, a
  name, a pasted error).
- **Challenge assumptions.** If something is unclear or suboptimal, say so and
  offer alternatives — back corrections with official docs first. Never agree
  just to be agreeable.

---

*Maintenance: this is a hand-distilled mirror of `.claude/rules/`. When a rule
there changes, update the matching bullet here (and vice-versa, routing the
canonical wording back into `.claude/rules/`). `/update-docs` and `/compound`
flag this file when rules change; without Claude Code, keep it in sync by
hand. Keep it a concise summary — link to depth, do not paste whole rules.*
