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

The screen is three horizontal bands. The middle band splits into two columns.

```
┌────────────────────────────────────────────────────┐
│ Header                                       3 rows│
├──────────────────────┬─────────────────────────────┤
│ Task tree        40% │ Output / Description    60% │
│                      │                             │
│                      │                     flexible│
├──────────────────────┴─────────────────────────────┤
│ Status bar                                   3 rows│
└────────────────────────────────────────────────────┘
```

## Panels

- **Header** — the product name and the detected system: distribution and
  resolved family. Fixed 3 rows.
- **Task tree** — the navigable list of categories and tasks. Left column, 40%
  of the width. Navigation is **drill-down**: exactly one level is on screen at
  a time, and opening a category replaces the list with its contents. Category
  rows are prefixed `›`; the panel title is the breadcrumb of the current path
  (`Remote Access › SSH`, or `Tasks` at the top level). Tasks unsupported on the
  running distribution stay visible, dimmed and annotated with the reason.
- **Output** — the running task's output, streamed line by line as it is
  produced, scrollable. Right column, 60% of the width. Retains the most recent
  2000 lines.
- **Description** — occupies the same area as Output before any task has run,
  showing what the selected task does. With a category selected it shows the
  category name and how many tasks it holds at any depth.
- **Status bar** — the current state (ready, running, finished, failed, or
  cancelled) plus the key hints. Fixed 3 rows.
- **Confirmation dialog** — overlays the centre of the screen, 60% × 40%, for
  destructive operations only. Modal: while it is open, all keys go to it.

## Style roles

| Role | Style | Where |
|------|-------|-------|
| `heading` | Cyan + bold | Category rows in the task tree |
| `selection` | Blue background + bold | The highlighted row |
| `disabled` | Dark grey | Tasks unsupported on this distribution |
| `progress` | Default | stdout lines in the output pane |
| `warning` | Yellow | stderr lines in the output pane |
| `danger` | Red + bold | The lockout warning in the confirmation dialog |
| `dialog-border` | Yellow | The confirmation dialog's frame |
| `choice-selected` | Black on white + bold | The selected answer in the dialog |
| `emphasis` | Bold | The product name and key names in the status bar |

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

The status bar reflects the selected row: the `Enter` hint reads *open* on a
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
