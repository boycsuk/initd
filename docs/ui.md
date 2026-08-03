# UI

> **What this file is.** The visual + navigational contract of the interactive
> terminal interface: the styles it uses, the panels the screen is divided
> into, and the keys that drive it. It answers "what does it look like and what
> can I reach", nothing more.
>
> **What this file is NOT.** Not widget documentation (blocks, lists and
> paragraphs live in source), not the scriptable surface (that is `cli.md`),
> not behavior (what the administrator can DO lives in `user-stories.md`).
>
> **Terminal, not web.** `initd` is a TUI, so the usual design tokens do not
> apply: there are no hex colors, no typefaces and no pixel spacing. A terminal
> supplies the font and resolves the 16 named ANSI colors against the user's
> own theme, so this file names *roles* and the named colors bound to them.
> Layout is expressed in rows and percentages, the only units a terminal has.
>
> **The full visual specification** lives beside this file as
> `tui-specification.html`: nine screens drawn as literal character grids at
> 80×24 and 120×40, plus the complete keyboard map, style table, layout
> geometry and state machine. This file is the summary contract; that one is
> the reference the implementation is diffed against. Where they disagree, this
> file describes what is built and the specification describes what is
> intended.
>
> **How to keep it true (no tooling required).** Plain Markdown — maintain it
> by hand in any editor. With Claude Code, `/update-docs` updates it from the
> diff. Update it whenever a panel is added/removed/renamed or its purpose
> changes, whenever a key binding changes, or whenever a style role is added or
> rebound. **Coverage over depth:** every panel, key and role must appear, even
> as a one-liner; a partial list that looks complete is worse than no list.

## Overview

A full-screen terminal interface built with `ratatui` over `crossterm`, started
by running `initd` with no arguments. It runs on the alternate screen in raw
mode, and restores the terminal on exit — including when the application fails,
so a crash never leaves an unusable shell.

Colors are the named ANSI set rather than fixed values, so the interface
inherits whatever palette the user's terminal defines. There is no light/dark
switch: the terminal already is one.

## Layout

The screen is four horizontal bands. The body splits into two columns. Every
band except the body is exactly one row: bordered chrome would spend six of the
twenty-four rows a terminal is assumed to have.

```
┌────────────────────────────────────────────────────┐
│ Header                                        1 row│
├──────────────────────┬─────────────────────────────┤
│ Task tree            │ Output / Detail             │
│                      │                             │
│ Body                 │                     flexible│
├──────────────────────┴─────────────────────────────┤
│ Status row                                    1 row│
│ Key bar                                       1 row│
└────────────────────────────────────────────────────┘
```

The body's split follows the terminal width:

| Width | Split |
|-------|-------|
| ≥ 100 columns | Tree fixed at 34 columns; the right pane absorbs the rest |
| 72–99 columns | Tree 42%, right pane 58% |
| < 72 columns | One pane at a time |

The tree takes a fixed width above 100 columns because its content has a fixed
natural width, so extra width belongs to the output, where lines are long and
wrapping hurts.

The key bar is dropped below 24 rows — it is a convenience, whereas the status
row is the only authoritative place the operator is told what the tool is
doing. Below **60 × 15** the interface is not drawn at all: it states the size
it needs instead, because a garbled layout on a production server is worse than
a clear refusal.

## Panels

- **Header** — the product name and version, the machine's hostname, the
  detected distribution, and how root is obtained (`root via sudo`). One
  borderless row. The hostname is emphasised because it answers the question an
  administrator with several terminals open actually has — *which machine am I
  about to change?* — and the privilege mechanism is stated up front so that
  "this will need a password" is known before a task is started rather than
  when one fails. A `? help` hint is right-aligned when the width allows, and
  dropped rather than wrapped when it does not.
- **Task tree** — the navigable list of categories and tasks. Left column.
  Navigation is **drill-down**: exactly one level is on screen at a time, and
  opening a category replaces the list with its contents. Category rows are
  prefixed `›` and carry their task count, right-aligned; the panel title is
  the breadcrumb of the current path (`Remote Access › SSH`, or `Tasks` at the
  top level). The bottom border carries the census of the level on screen
  (`2 tasks`, `1 category`), which costs no rows. Tasks unsupported on the
  running distribution stay visible and dimmed.
- **Output** — the running task's output, streamed line by line as it is
  produced, scrollable. Right column. Retains the most recent 2000 lines.
- **Detail** — occupies the same area as Output before any task has run,
  showing what the selected task does, titled with the task's own name. With a
  category selected it shows the category name and how many tasks it holds at
  any depth.
- **Status row** — the state pill plus a message. One borderless row.
- **Key bar** — the key hints for the current row and state. One borderless
  row, dropped on terminals shorter than 24 rows.
- **Confirmation dialog** — overlays the centre of the screen, 60% × 40%, for
  destructive operations only. Modal: while it is open, all keys go to it.

## Row markers

Meaning is carried by a glyph, never by colour alone, so a monochrome or
`NO_COLOR` terminal loses nothing and `DIM` rendering identically to normal
(as some themes do) costs no information.

| Marker | Meaning |
|--------|---------|
| `›` | The row opens onto another level |
| `!` | The task is destructive and asks for confirmation |
| `·` | The task is not supported on this host |

## Status row

One authoritative place for what the tool is doing. It opens with a pill in the
same cells at the left edge, so the operator's eye never searches for it, and
the word carries the meaning alone when colour is absent.

| Pill | Meaning |
|------|---------|
| `READY` | Waiting for input |
| `RUNNING` | A task is running |
| `DONE` | The last task succeeded |
| `FAILED` | The last task failed |
| `CANCELLED` | The last task was interrupted before it finished |
| `CONFIRM` | A confirmation dialog is open |
| `UNSUPPORTED` | The selected task cannot run on this host |

Two of these describe the cursor rather than the past and therefore override
whatever the last action left behind: `CONFIRM` while a dialog is open, and
`UNSUPPORTED` when the selected row cannot run here. The pill must always state
what pressing `Enter` would do now.

### Transient messages

Refusals — "already at the top level", "not supported on arch" — flash beside
the pill for two seconds and then disappear on their own. They override the
state's message but **never** the pill: losing sight of what the tool is doing
because something was refused is exactly what the separation prevents.

There are no toasts and no overlays. A message that occludes content is
unacceptable when the content is the log of a command running as root.

## Truncation

Text too long for its column is always marked with `…`, never clipped in
silence — a title cut to `Install and enable the SSH ser` reads as a real name,
so the operator cannot tell anything is missing.

Which end is dropped depends on which end identifies the text:

| Text | Loses its | Example |
|------|-----------|---------|
| Breadcrumbs | head | `… Access › SSH › Configuration` |
| Task titles | tail | `Install and enable the SSH s…` |

A path is identified by where it ends, a task by how its name starts.

## Style roles

Every style the interface draws is named once, in `src/tui/style.rs`, and
referenced from the call sites. A style built where it is used drifts from its
siblings the moment either is edited, so call sites never construct one.

Two rules govern the table:

1. **Colour is semantic, never decorative.** The terminal theme owns the hues;
   `Reset` means "whatever the user's foreground is".
2. **No signal is carried by colour alone.** Every coloured state is also
   marked by a glyph or a word.

| Role | Style | Where |
|------|-------|-------|
| `heading` | Cyan + bold | Expanded category rows |
| `category_collapsed` | Cyan | Collapsed category rows |
| `pane_title` | Cyan | Block titles: task title, breadcrumb |
| `block_subtitle` | White + dim | Bottom titles, section headers |
| `normal` | Reset | Task rows, detail body, child stdout |
| `selection_focused` | White on blue + bold | The selected row while its pane has focus |
| `selection_unfocused` | White + bold + underlined | The selected row while focus is elsewhere |
| `selection_disabled` | Black on white | A selected row that cannot run |
| `disabled` | White + dim | Unsupported rows, inert hints |
| `flag_danger` | Red + bold | The `!` marker |
| `flag_input` | Yellow | The `…` marker |
| `flag_unsupported` | White + dim | The `·` marker |
| `result_ok` | Green | The `✓` glyph and `ok` lines |
| `result_fail` | Red + bold | The `✗` glyph |
| `tree_guide` | White + dim | Depth guides and rules |
| `scrollbar_track` | White + dim | Scrollbar track and arrows |
| `scrollbar_thumb` | White | Scrollbar thumb |
| `border_focused` | Cyan | The focused pane's border |
| `border_unfocused` | White + dim | Every other pane's border |
| `output_command` | White + dim | The `$` prefix and echoed commands |
| `output_warn` | Yellow | `W:` lines and non-fatal notes |
| `output_error` | Red + bold | stderr on failure, invalid config lines |
| `output_cursor` | Reversed | The live write position |
| `danger_text` | Red + bold | Dialog headlines, the rollback countdown |
| `emphasis` | White + bold | Values that change, key words in dialogs |
| `dialog_border_danger` | Red + bold | Confirmation dialog frames |
| `dialog_border_input` | Blue | Input forms and field boxes |
| `choice_selected` | Reversed + bold | The preselected safe answer |
| `choice_normal` | White + dim | The other answer |
| `search_match` | Black on yellow | The matched substring in a filtered row |
| `status_ready` | Black on green + bold | The `READY` and `DONE` pills |
| `status_busy` | Black on yellow + bold | The `RUNNING` and `VERIFY` pills |
| `status_error` | Black on red + bold | The `FAILED` and `CONFIRM` pills |
| `status_input` | Black on blue + bold | The `INPUT` and `SEARCH` pills |
| `status_inert` | Black on white + bold | The `UNSUPPORTED` pill |
| `keybar_key` | Reset + bold | The key glyph in the key bar |
| `keybar_label` | White + dim | Its description |
| `gauge` | Green | The step-progress gauge |

`selection_focused` sets an explicit foreground/background pair rather than
reversing: reversal swaps per cell, so a red destructive marker on a reversed
row would render as a red block and the row's meaning would invert with it.

Roles for elements the interface does not draw yet — dialog borders, the gauge,
result glyphs, search highlighting — are declared here and in source so the
table stays one readable reference, and so a new call site picks a role instead
of inventing a colour.

## Keys

### Task tree

| Key | Action |
|-----|--------|
| `↑` / `k` | Move to the previous row (categories included) |
| `↓` / `j` | Move to the next row |
| `Enter` | Open the selected category, or run the selected task; destructive tasks open the dialog first |
| `Esc` / `Backspace` / `←` / `h` | Go back to the parent level; at the top level it reports rather than quitting |
| `PageUp` | Scroll the output pane towards older lines |
| `PageDown` | Scroll the output pane back towards the newest |
| `q` | Quit, from any level |

Every row is selectable: a category that could not be selected could not be
opened. `Esc` means "go back" rather than "quit", so pressing it one level too
many cannot drop the user out of the program — `q` is the only way out.

The key bar reflects the selected row: the `Enter` hint reads *open* on a
category and *run* on a task, and the `Esc` hint appears only below the top
level.

### Confirmation dialog

| Key | Action |
|-----|--------|
| `Tab` / `←` / `→` | Switch between Yes and No |
| `Enter` | Confirm the current answer |
| `Esc` | Cancel without running the task |

The dialog opens on **No**, so a stray `Enter` cannot trigger a destructive
operation.

## Running a privileged task

When a task needs root, the interface hands the terminal back before the child
process starts: it leaves the alternate screen and disables raw mode, so the
password prompt is legible and accepts input normally. Once the task ends, raw
mode and the alternate screen are restored and the screen is cleared.

The clear is required, not cosmetic: programs that query the terminal's colors
otherwise leave raw ANSI RGB values printed inside the restored interface.

Input events are not read while the child runs, so the interface never competes
with the password prompt for keystrokes.
