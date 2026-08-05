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

Below 72 columns the two panes become **two views of one area**, switched with
`Tab`. The header trades the host facts for a `tasks / output` indicator, since
nothing else would say which of the two is showing and `Tab` would look like it
did nothing.

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
  produced, scrollable. Right column. Retains the most recent 5000 lines in a
  ring buffer, dropping the oldest. The bottom border states whether the view
  is pinned to the newest output (`follow`) or has been scrolled away
  (`detached`), and while following, a `▌` cursor marks where the next line
  will land — a quiet command and a frozen screen otherwise look identical.
- **Detail** — occupies the same area as Output before any task has run,
  showing what the selected task does, titled with the task's own name. With a
  category selected it shows the category name and how many tasks it holds at
  any depth.
- **Status row** — the state pill plus a message. One borderless row.
- **Key bar** — the key hints for the current row and state. One borderless
  row, dropped on terminals shorter than 24 rows.
- **Parameter form** — overlays the centre of the screen for tasks that collect
  values (a port, a username, a public key). Modal. Each field shows its label,
  a boxed input, and a note beneath stating either what is wrong with the value
  or what it parsed as. Validation runs on every keystroke, so the consequences
  of a value are visible before `Enter` rather than after.
- **Confirmation dialog** — overlays the centre of the screen, 60% × 40%, for
  destructive operations only. Modal: while it is open, all keys go to it.

- **Help overlay** — every binding the interface has, grouped by where it
  applies. Opened with `?` from anywhere, including on top of a dialog, since
  the moment someone needs the key list is the moment they do not know which
  key to press. Scrollable, because the section worth reading most — the keys
  that cannot be guessed from anywhere else — is the one at the end.
- **Verification banner** — replaces the detail pane after a change that could
  sever the administrator's own access. States that the change is applied but
  not yet kept, counts down to the automatic revert, and names the two keys.
  The output pane keeps the rest of the column, because the log of what just
  happened is the evidence for the decision.

The order is always **values, then consent, then the work**: a confirmation
states what will happen, and it cannot do that before it knows the values.

## Row markers

Meaning is carried by a glyph, never by colour alone, so a monochrome or
`NO_COLOR` terminal loses nothing and `DIM` rendering identically to normal
(as some themes do) costs no information.

| Marker | Meaning |
|--------|---------|
| `›` | The row opens onto another level |
| `!` | The task is destructive and asks for confirmation |
| `…` | The task collects parameters before it runs |
| `·` | The task is not supported on this host |

A row carries at most one flag, and they rank in that order: a task that is
both destructive and parameterised shows `!`, since the warning outranks the
notice.

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
| `VERIFY` | A change is applied but not yet kept |
| `CONFIRM` | A confirmation dialog is open |
| `INPUT` | A parameter form is open, collecting input before the task runs |
| `UNSUPPORTED` | The selected task cannot run on this host |

Three of these describe the cursor rather than the past and therefore override
whatever the last action left behind: `CONFIRM` while a dialog is open, `INPUT`
while a form is, and `UNSUPPORTED` when the selected row cannot run here. The
pill must always state what pressing `Enter` would do now.

`CONFIRM` outranks `INPUT` where both apply: a destructive task collects its
parameters first and confirms after, so once the confirmation is up it is the
live question.

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
| `consequence` | Yellow | The `!` marker on a consequence the tool can check |
| `consequence_external` | Yellow + bold | The `⚠` marker on one it cannot |
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
| `status_error` | Black on red + bold | The `FAILED`, `CANCELLED` and `CONFIRM` pills |
| `status_input` | Black on blue + bold | The `INPUT` pill |
| `status_inert` | Black on white + bold | The `UNSUPPORTED` pill |
| `keybar_key` | Reset + bold | The key glyph in the key bar |
| `keybar_label` | White + dim | Its description |
| `gauge` | Green | The step-progress gauge |

`selection_focused` sets an explicit foreground/background pair rather than
reversing: reversal swaps per cell, so a red destructive marker on a reversed
row would render as a red block and the row's meaning would invert with it.

Roles for elements the interface does not draw yet — the gauge, result glyphs,
search highlighting — are declared here and in source so the table stays one
readable reference, and so a new call site picks a role instead of inventing a
colour.

## Keys

### Anywhere

| Key | Action |
|-----|--------|
| `Tab` | Move focus between the tree and the output |
| `?` | Open the help overlay |
| `q` | Quit, from any level and either pane |

`j` and `k` mean "next" and "previous" in both panes, so something has to say
which one they address. That something is `Tab` and **nothing else**:
overloading a movement key with focus is how keys start leaking between panes.

The focused pane is drawn with a cyan border; the other is dim. The tree's
selected row stays visible when focus leaves it, drawn underlined rather than
highlighted — losing the cursor on `Tab` would mean hunting for it again on the
way back.

### Task tree

| Key | Action |
|-----|--------|
| `↑` / `k` | Move to the previous row (categories included) |
| `↓` / `j` | Move to the next row |
| `g` / `G` | Jump to the first / last row of the level |
| `Enter` | Open the selected category, or run the selected task; destructive tasks open the dialog first |
| `Esc` / `Backspace` / `←` / `h` | Go back to the parent level; at the top level it reports rather than quitting |

Every row is selectable: a category that could not be selected could not be
opened. `Esc` means "go back" rather than "quit", so pressing it one level too
many cannot drop the user out of the program — `q` is the only way out.

A scrollbar appears on the right edge of the tree only when the level overflows
the pane; a track drawn against a level that fits is a permanent hint that
content is hidden when none is.

### Output pane

| Key | Action |
|-----|--------|
| `↑` / `k` | Scroll one line towards older output, detaching from the tail |
| `↓` / `j` | Scroll one line back towards the newest |
| `PageUp` / `PageDown` | Scroll by ten lines |
| `g` | Jump to the oldest retained line |
| `G` / `f` | Jump to the newest output and follow it again |
| `w` | Toggle wrapping of long lines |
| `Esc` | Return focus to the tree |

Any upward scroll detaches the view from the tail, so reading back through a
log is never interrupted by new arrivals. Scrolling back to the bottom
re-attaches on its own — the operator has caught up, and needing another key to
resume following would be a step with no purpose.

### The key bar

The hints follow the focused pane and the row under the cursor rather than
listing every binding: a bar that never changes is one the operator stops
reading. On the tree the `Enter` hint reads *open* on a category and *run* on a
task; `Esc back` appears only below the top level, and `Tab output` only once
there is output to switch to.

### Parameter form (modal)

Every printable character is **literal** here — `j`, `k`, `q` and `/` type
themselves rather than acting as commands. Only the keys below stay commands.

| Key | Action |
|-----|--------|
| `Tab` / `↓` | Next field |
| `Shift-Tab` / `↑` | Previous field |
| `Enter` | Next field, or submit on the last one |
| `←` / `→` | Move the cursor |
| `Home` / `End` / `Ctrl-A` / `Ctrl-E` | Jump to the start or end of the value |
| `Backspace` / `Delete` | Delete before or under the cursor |
| `Ctrl-U` / `Ctrl-K` | Clear before or after the cursor |
| `Ctrl-W` | Delete the previous word (readline's convention wins here) |
| `Esc` | Cancel |

Submitting with a field that would be rejected moves the cursor to that field
rather than merely refusing — the operator should not have to hunt for which
one is the problem.

`Esc` on a form with typed values asks first: the second `Esc` discards. Any
other key in between disarms it, so a stale prompt cannot be answered by a
keystroke aimed at something else. An untouched form closes on the first `Esc`,
since there is nothing to lose.

A field rejects characters its kind cannot contain — a port field takes only
digits — so a value that could never be accepted cannot be typed at all. Long
values scroll horizontally with a `…` marking text dropped from the left; a
public key is verified by what it *parses* to (type and comment, echoed beneath
the field), because a 380-character key cannot be checked by reading it.

### Help overlay

| Key | Action |
|-----|--------|
| `↑` / `k` / `↓` / `j` | Scroll a line |
| `PageUp` / `PageDown` | Scroll a page |
| `g` / `Home` | Top of the list |
| `G` / `End` | Bottom of the list |
| *anything else* | Close |

Closing on any other key, including `?` itself, is deliberate: an overlay that
has to be dismissed a particular way traps whoever opened it by accident. The
closing key does **not** also do whatever it normally would.

### While a task is running

The interface stays open — scrolling, switching panes and reading all work —
but nothing new may be started, and nothing already applied may be answered.

| Key | Action |
|-----|--------|
| `Ctrl-C` | Ask the task to stop at its next step boundary |
| `↑` / `↓` / `PageUp` / `PageDown` | Scroll the output |
| `w` | Toggle wrapping |
| `Tab` | Switch panes |
| `?` | Help |
| `q` | Refused, naming `Ctrl-C` as the way to stop |
| *anything else* | Refused: a task is already running |

**Cancellation is cooperative, and honest about it.** `Ctrl-C` asks the task to
stop between two commands rather than killing it mid-write — a half-written
configuration file is how a machine ends up in a state nobody chose. Until the
current step ends the status still reads `RUNNING`, with the message
*stopping after the current step*; only once the task has actually stopped does
it read `CANCELLED`, and it says where it got to.

The status row carries two liveness signals at its right edge while a task
runs: a one-character ASCII spinner and a wall-clock timer, both driven by the
clock rather than by arriving output. Over a slow link a quiet command and a
frozen screen are otherwise indistinguishable. The spinner is ASCII rather than
braille, which is missing or double-width in too many of the fonts a server
console actually has.

### Verification window (semi-modal)

Open after a change that could end the administrator's own session. Reading is
never blocked — the log is what the decision rests on — but nothing new may be
started until this change is settled.

| Key | Action |
|-----|--------|
| `K` | Keep the change |
| `R` | Put the previous configuration back now |
| `↑` / `↓` / `PageUp` / `PageDown` | Scroll the output |
| *timer* | Puts the change back on its own after 60 seconds |
| *anything else* | Refused, restating what the two answers are |

`K` and `R` are **uppercase deliberately**: lowercase `k` is "move up"
everywhere else in this interface, and this is the one place where a mistyped
navigation key would do something unrecoverable.

`q` is refused here and is not offered in the key bar. Quitting would abandon
the change with nobody left to put it back — the one outcome the window exists
to prevent.

The default outcome of silence is the safe one. An administrator who has just
locked themselves out is, by definition, unable to press a key to undo it, so
the revert happens without them.

Losing the session counts as silence, not as confirmation. A dropped connection
delivers `SIGHUP` and an ordinary `kill` or `systemctl stop` delivers `SIGTERM`;
both are caught, and an unconfirmed change goes back before the process exits.
This is the case the window exists for rather than an edge of it — `ssh.harden`
can sever the very connection that would confirm it.

Two things it cannot cover, and the banner says so rather than implying
otherwise with a line reading **"Reverts while this session lives."**: `SIGKILL`
cannot be caught by any program, and a machine losing power runs no code at
all. In both the change stays applied. Stating the limit is what makes the rest
of the banner trustworthy; a promise with a silent exception teaches people to
disbelieve all of it.

### Confirmation dialog (modal)

| Key | Action |
|-----|--------|
| `Tab` / `←` / `→` | Switch between Yes and No |
| `y` | Apply |
| `n` / `Esc` | Cancel |
| `Enter` | Confirm the current answer |

The dialog opens on **No**, so a stray `Enter` cannot trigger a destructive
operation. `n` and `Esc` both mean the safe answer, so the reflex to back out
lands on it whichever key it reaches for.

## Running a privileged task

The password is asked for **once, before the interface starts**, while the
terminal is still ordinary and `sudo` can draw its own prompt. `initd` never
reads it: the prompt belongs to sudo, and what the tool gets is the
authentication timestamp sudo leaves behind. Later privileged commands reuse
that timestamp, which is what lets a task's output stream into the pane instead
of the interface being torn down and rebuilt around every command.

Two properties this depends on, measured on real Debian 13 and Arch systems and
recorded in `sudo-timestamp-findings.md`:

- Both key the timestamp by **terminal**, so spawned commands inherit stdin
  rather than being given `/dev/null` — a process with no terminal is refused
  even when the session that spawned it has authenticated.
- Arch expires it after **five minutes**, not the fifteen usually assumed. Any
  privileged command extends the window, so a task in progress keeps it open.

A refusal at startup is not fatal. The operator may have cancelled the prompt,
or the mechanism may not support this at all — `doas` has no equivalent and
`run0` defers to polkit — and privileged commands still work either way. They
simply prompt when they run.
