# Conventions

> **What this file is.** The coding conventions of this project, distilled so
> that any tool or contributor can follow them — including ones that do NOT run
> Claude Code and therefore never see `~/.claude/rules/`. If you are an AI or an
> editor working in this repo (Xcode, a sandboxed subdir, a different
> assistant), **read this file and follow it** before writing or changing code.
>
> **Source of truth.** The canonical, always-current version of these rules
> lives in `~/.claude/rules/` (`code-quality.md`, `security.md`, `workflow.md`,
> `ai-collaboration.md`) — global Claude Code config, outside this repository,
> loaded automatically in every project. This file is a portable mirror of those
> rules for everyone else. If the two ever disagree: for the maintainer, who has
> the global rules loaded, `~/.claude/rules/` wins and this mirror should be
> re-synced (see the footer); for everyone else, who cannot see that directory,
> **this file is the reference** — follow it. A project may also add its own
> `.claude/rules/<topic>.md`; those are project-local additions on top of the
> global set, not the canonical source above.
>
> **What this file is NOT.** Not the product contract — that is `cli.md`
> (the programmatic contract), `ui.md` (visual), and `user-stories.md`
> (behavior). This file is about *how to write the code*, not *what the code
> does*.

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
- **No logging framework.** A task reports what it is doing through
  `Progress`, which the CLI prints and the TUI streams into its output pane.
  There is no logger and no log file: this tool runs one operation at a time in
  front of the person who asked for it.
- **User-facing text lives in the message catalogue**, never in the code that
  raises it. Errors and interface strings carry structured data; `src/i18n/`
  renders them. The catalogue is a closed enum rendered by an exhaustive match,
  so a missing translation fails to compile.
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

This tool runs as root on someone's server, which is what makes the list below
specific rather than generic.

- **Validate at every boundary.** All external input (parameters, files,
  environment) is validated before use. A CLI argument never passes through the
  interactive form's keystroke filter, so the CLI applies the same validation
  itself rather than trusting that it was already done.
- **No injection: pass arguments, never assemble a command line.** Everything
  goes through `Executor` with arguments as separate `argv` elements, so a
  username or a path cannot be reinterpreted as syntax. Where a value must
  reach a program that parses it — a `grep` pattern, a regular expression —
  that is a second syntax and needs escaping of its own.
- **Least privilege.** A command runs privileged only when it needs to be.
  `getent passwd` asks a question any account may ask, so it does not spend an
  escalation on it.
- **Secrets are written into a file whose mode is already right**, never
  written and then tightened. Create it empty, set the mode, then write: an
  empty file discloses nothing, and the window between two calls is long enough
  for any account on the box.
- **Never log or serialize a secret.** A private key is printed once to the
  operator and stored nowhere by this tool.
- **No homegrown crypto.** Key material comes from the system's own tools
  (`wg genkey`, `ssh-keygen`), never from anything written here.
- **Verify before executing.** The installer checks a published digest before
  it runs a downloaded binary, and states in the script what that does *not*
  defend against.
- **Pin and audit dependencies.** `Cargo.lock` is committed; `cargo deny check`
  runs in CI. Adding a dependency is a decision, not a convenience.
- **Prevent TOCTOU where the check and the act must be inseparable.**
  `users.lock-root` re-reads its precondition immediately before the
  irreversible step, because several privileged commands separate the two.

## Don't

Non-negotiable in this codebase. Each exists because the alternative was tried,
measured, or would defeat the architecture:

- **Don't branch on the distribution inside a task.** If a task needs
  `match distro`, the missing abstraction belongs in a domain trait. With N
  tasks, per-task branching repeats the same match N times and every new
  distribution edits all of them. The one place a family may be named outside a
  backend is `Task::support`, where whether a task *runs* somewhere is a
  decision rather than a spelling.
- **Don't call `std::process::Command` outside `src/exec/`.** Every command
  goes through `Executor`, or adding a remote transport later becomes a
  full refactor instead of a second implementation.
- **Don't use `unwrap()` / `expect()` / `panic!` in production paths.** This
  runs as root: a panic mid-operation can leave a system half-configured.
  Propagate the error and report it.
- **Don't hardcode paths to binaries** (`/usr/bin/apt`). They differ across
  distributions — resolve through `PATH`.
- **Don't assume a package name is the same across distributions**
  (`docker.io` vs `docker` vs `docker-ce`). Names belong in the per-family
  backend.
- **Don't run a destructive operation without an explicit confirmation step.**
- **Don't add a dependency without asking.** Every one is audited.
- **Don't mix a refactor and a feature in one commit** — it complicates
  rollback.

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
  matching file in `docs/` (`cli.md` / `ui.md` / `user-stories.md`).

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

*Maintenance: this is a hand-distilled mirror of `~/.claude/rules/`. When a rule
there changes, update the matching bullet here (and vice-versa, routing the
canonical wording back into `~/.claude/rules/`). `/update-docs` and `/compound`
flag this file when rules change; without Claude Code, keep it in sync by
hand. Keep it a concise summary — link to depth, do not paste whole rules.*
