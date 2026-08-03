# SPEC — Recursive category tree

> Status: proposed, not implemented.
> Scope: infrastructure only. No new administration tasks. No new CLI parameters.

## Problem

The task tree is a flat, single-level list. `TaskGroup { title, tasks }` holds a
`Vec<Box<dyn Task>>` and nothing else, so a group cannot contain another group.
Today there is exactly one group (`"SSH"`) with four tasks, which hides the
limitation rather than removing it.

As administration areas land (users, firewall, packages, system), a flat list
grows into an undifferentiated wall of rows. Some areas also want internal
structure — SSH alone plausibly splits into service management, configuration
hardening and key administration — and a single level cannot express it.

## Decision

Replace `TaskGroup` with a recursive node: a category holds an ordered list of
children, where a child is either a task or another category. Depth is
unbounded by the type; it is bounded only by what the tree declares.

The TUI gains collapse/expand, because a recursive tree rendered fully expanded
is worse than the flat list it replaces.

**Rejected — single-level collapsible groups.** Cheaper now (`TaskGroup` keeps
its shape, the TUI only adds a folded flag), but it re-runs this same migration
the first time an area needs sub-structure, and it re-touches the same three
call sites. The recursive model costs one extra type today and admits any depth
without rework.

**Rejected — categories as a TUI-only concept.** The tree is the domain model of
what the tool can do; the TUI renders it. Encoding hierarchy in the renderer
would leave `tasks::tree()` unable to answer "what is under SSH" and force the
CLI to reconstruct hierarchy from id prefixes.

## Model

In `src/tasks/mod.rs`:

```rust
/// A node in the task tree: either a runnable task or a category of nodes.
pub enum Node {
    Task(Box<dyn Task>),
    Category(Category),
}

/// A named group of nodes, which may itself contain categories.
pub struct Category {
    pub title: &'static str,
    pub children: Vec<Node>,
}
```

`Task` itself is unchanged — no new required method, no touched implementation
in `ssh.rs`. This is what keeps the refactor contained: the four existing task
types compile untouched.

`tree()` returns `Vec<Node>` (a forest of top-level categories) rather than
`Vec<TaskGroup>`.

`find(id)` walks the tree recursively instead of a single `flat_map`. Ids stay
globally unique and keep their existing values (`ssh.install`, …), so nothing
that references a task by id changes.

### Initial shape

SSH sits under a top-level area that will also hold WireGuard, and splits into
its natural sub-areas — shipping a recursive tree with no nesting would not
exercise the model:

```
Remote Access
└── SSH
    ├── Service
    │   └── ssh.install          Install and enable
    ├── Configuration
    │   ├── ssh.harden           Harden the configuration
    │   └── ssh.change-port      Change the listening port
    └── Keys
        └── ssh.authorize-key    Authorise a public key
```

`Remote Access` is named for what its members do rather than for a protocol:
SSH grants shell access, WireGuard grants network access, and both are ways in
from outside. `Network` would be broader than intended (firewall, DNS,
interfaces belong there too) and `Access` alone reads as local users and
permissions.

Task ids are unchanged. Only their position in the tree is new.

## TUI — drill-down navigation

`src/tui/app.rs` currently flattens the whole tree into `Vec<Entry>` where
`Entry::Group` is a non-selectable heading. That model is replaced entirely:
**the list shows exactly one level at a time.**

Entering a category replaces the list with that category's children; going back
restores the parent, with the cursor where it was left. There is **no
indentation** — with a single level on screen there is no depth to convey by
spacing, and the breadcrumb carries the location instead.

State in `App`:

```rust
/// Path from the root to the category currently being shown.
///
/// Empty means the root level. Each entry is the index of the chosen child
/// within its parent, so the path survives no matter how the tree is shaped.
path: Vec<usize>,

/// Cursor position per level, so going back restores the previous selection.
cursor_stack: Vec<usize>,
```

Rows are derived from `path` on each render rather than stored: the tree is
tens of nodes, and deriving keeps a single source of truth.

Changes:

- **Categories become selectable.** Today headings are skipped by
  `select_next`/`select_previous`; a category you cannot select is a category
  you cannot enter, so both drop their "skip headings" filter.
- **`Enter` is dispatched by row type**: on a category it descends; on a task
  it keeps today's behaviour (support check → confirm if destructive → run).
- **`Esc`/`Backspace` goes up one level.** `Esc` currently quits the program.
  It is rebound to "go back", quitting only at the root level, which is what
  the key means in every drill-down interface. `q` keeps quitting outright from
  anywhere — otherwise there is no way out from a deep level without repeated
  `Esc`.
- **A breadcrumb replaces the list title.** `Remote Access › SSH` tells the
  user where they are; without it, a single-level list is ambiguous.
- **Description pane**: with a category selected, it shows the category title
  and how many tasks it contains, rather than going blank.

### Rejected

**Folding in place** (the whole tree in one list, `Enter` expands/collapses,
indented). It keeps the full context visible, but the tree gets deep enough
(`Remote Access > SSH > Configuration > task`) that indentation eats horizontal
space in a 40%-wide panel, and the user asked for drill-down explicitly.

**Miller columns** (two panels side by side). Shows two levels at once, but the
task list already shares the width with the output pane; a third column would
leave none of them usable.

## CLI

**No new subcommands, no new arguments, no new flags.** The CLI surface is
unchanged.

`cmd_list` in `main.rs` must still be adapted: it iterates `group.tasks`
directly and stops compiling when the type becomes recursive. It gets a
recursive walk that prints the tree indented by depth, keeping the existing
`[ ]`/`[!]` support marker and measured id-width alignment.

This is a consequence of the type change, not added surface. Output shape
changes (indentation reflects nesting), so `docs/cli.md` needs the sample
output updated.

## Files touched

| File | Change |
| --- | --- |
| `src/tasks/mod.rs` | `Node`/`Category` replace `TaskGroup`; recursive `tree()` and `find()` |
| `src/tui/app.rs` | `Row` replaces `Entry`; folding, depth indent, `Enter` dispatch, selectable categories |
| `src/main.rs` | `cmd_list` recursive walk (compile-forced, no new surface) |
| `docs/ui.md` | Fold markers, `Enter` on a category, indentation |
| `docs/cli.md` | Updated `list` sample output |
| `CHANGELOG.md` | Entry under `[Unreleased] → Changed` |

`src/tasks/ssh.rs` is **not** touched: the task types are unchanged, only how
`tasks()` assembles them into categories.

## Tests

Existing tests that must keep passing, adapted to the recursive walk:
`every_task_has_a_unique_id`, `every_task_supports_at_least_one_family`,
`tasks_can_be_found_by_id`, `the_tree_contains_every_task`.

New, in `tasks::tests`:
- `find` locates a task nested two levels deep (`ssh.authorize-key`).
- `find` returns `None` for a category title — categories are not tasks and
  must not be runnable by id.
- Every category has at least one child; an empty category is a bug, since the
  TUI would render an unopenable row.

New, in `tui::app::tests`:
- The root level lists only top-level categories, not their descendants.
- Entering a category shows its children and only its children.
- Going back restores the parent level *and* the cursor position it had.
- Going back at the root level does not quit and does not underflow the path.
- Navigation reaches every row, categories included (replaces the current
  "cursor never lands on a heading" assertion, which inverts under this design).
- Entering a category leaves the cursor on a valid row of the new level.
- A task nested three levels deep is reachable by descending, and running it
  dispatches to that task.

## Order of work

One commit per step; each compiles and passes.

1. **Model.** `Node`/`Category`, recursive `tree()`/`find()`, SSH restructured
   under `Remote Access`. Adapt `cmd_list` and the TUI to the new type, still
   rendering every level at once. No user-visible change beyond the new
   grouping. Tests adapted.
2. **Drill-down.** `path`/`cursor_stack`, one level per screen, `Enter` to
   descend, `Esc`/`Backspace` to go back, breadcrumb. New TUI tests.
3. **Docs.** `/update-docs` over `docs/ui.md` and `docs/cli.md`, CHANGELOG entry.

Step 1 is a pure refactor with no user-visible change beyond grouping; step 2 is
the feature. Keeping them apart is what `CLAUDE.md` requires ("do not mix
refactor with feature in the same commit") and makes step 2 revertible on its
own.

## Open question

The tree is currently built entirely in code, and `tasks()` in `ssh.rs` returns
a flat `Vec<Box<dyn Task>>` that `tree()` wraps. With sub-categories, the
question is whether `ssh.rs` exposes its own `Category` (owning its internal
structure) or `tasks/mod.rs` assembles the sub-categories from a flat list.

Recommendation: **`ssh.rs` returns its own `Category`.** The area owns how it is
subdivided, and `tree()` stays a one-line list of areas — which is what keeps
adding an area a one-file change, matching the rule that already governs
backends.
