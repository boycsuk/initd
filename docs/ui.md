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
> **This file is the visual contract**, not a summary of one. A rendered
> specification used to sit beside it; it was removed rather than kept in step,
> because two documents describing one interface diverge and the reader cannot
> tell which is current. What the implementation is diffed against are the
> rendering tests, which assert on a real buffer.
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

The screen is three horizontal bands. The body splits into two columns. Every
band except the body is exactly one row: bordered chrome would spend six of the
twenty-four rows a terminal is assumed to have.

```
┌────────────────────────────────────────────────────┐
│ Header                                        1 row│
├──────────────────────┬─────────────────────────────┤
│ Task tree            │ Output / Detail             │
│                      │                             │
│ Body                 │                     flexible│
│                      │                             │
│ └ census ────────────┴───────────── status ───────┘│
├────────────────────────────────────────────────────┤
│ Key bar                                       1 row│
└────────────────────────────────────────────────────┘
```

The status has no band of its own. It rides the bottom border of the pane on
the right, the way the tree's census rides its own, so it costs no rows — the
row it used to occupy belongs to the body.

The body's split follows the terminal width:

| Width | Split |
|-------|-------|
| ≥ 100 columns | Tree fixed at 46 columns; the right pane absorbs the rest |
| 72–99 columns | Tree 42%, right pane 58% |
| < 72 columns | One pane at a time |

The tree takes a fixed width above 100 columns because its content has a
natural one, so extra width belongs to the output, where lines are long and
wrapping hurts. Giving the tree a share of a wide terminal would spend it on
padding.

**That width is measured, not chosen.** The longest task title is 40 cells and
a row spends six more — two of border, two of marker, one of flag, and the
space separating the title from it — so 46 is the width at which no task in
the tree is truncated. A task added with a longer name shortens the others,
silently: a truncated title still renders, it just cannot be read. A test
compares the constant against the tree so that the day it stops being true is
a failing build rather than a screen nobody can use.

Below 72 columns the two panes become **two views of one area**, switched with
`Tab`. The header trades the host facts for a `tasks / output` indicator, since
nothing else would say which of the two is showing and `Tab` would look like it
did nothing.

The key bar is dropped below 24 rows — it is a convenience, and it is now the
only band that can be given up at all, since the status costs no row to keep.
Below **60 × 15** the interface is not drawn at all: it states the size it needs
instead, because a garbled layout on a production server is worse than a clear
refusal.

## Modals

The five dialogs — confirmation, parameter form, help overlay, search,
recorded changes — are drawn to one set of rules, so a frame does not move for
reasons the operator cannot name:

| Rule | Value |
|------|-------|
| Width | 72 columns, clamped to the terminal |
| Height | measured from the content; never a share of the screen |
| Gutter | 2 cells between the frame and any text |
| Inset | one blank row at each end of the content |
| Footer | separated from the content by a rule spanning the frame |

They had three widths between them — 72, 70 and 64 — each defensible alone and
none chosen against the others. The width's floor is the parameter form's
footer, the longest fixed string any of them draws: footers are adjacent spans
that neither wrap nor truncate, so a dialog one cell too narrow silently loses
`cancel`, the key out of a modal.

The search and recorded-changes overlays keep the gutter vertically only. Its selected row is drawn
as a filled band, and one stopping two cells short of each border would read as
a highlight that failed to paint rather than as a margin.

## Recorded changes

`h` opens a list of the configuration changes this tool has recorded, newest
first. Each row names the task that made the change, when, and the file — the
task because a file with ten recorded states is ten indistinguishable
timestamps without it.

Semi-modal, like search: it takes the movement keys (`↑↓`, `Home`/`End`) and
`Esc` closes it having changed nothing. `Enter` offers to put the selected
state back, through the same confirmation as any other change that can end the
session — at the lockout tier, with the red frame.

`h` was the fourth way to leave a category — after `Esc`, `Backspace` and `←` —
and was a capital `H` for as long as that was true: one keystroke from a key
pressed by reflex is a poor place for a list that rewrites configuration files.
Retiring the vim movement keys freed it, and freed the objection with it, since
nothing now presses `h` without meaning to.

A host where nothing has been recorded gets a sentence saying so rather than an
empty list, since an empty list inside a bordered frame reads as a view that
failed to load.

A restore that is refused — because the file has been edited since, or because
the copy is damaged — reports into the output pane and sets the status row to
`not restored`. That wording is deliberate: the refusals leave the machine
exactly as it was, which is a different thing from a command that broke.

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
  running distribution stay visible and dimmed, and selecting one shows **why**
  in the detail panel — which repository does not carry it, which shipped
  configuration would override it, which installer publishes nothing to verify.
  Dimming says a task is refused; only the reason distinguishes a missing
  package from a deliberate policy from a bug worth reporting.
- **Output** — the running task's output, streamed line by line as it is
  produced, scrollable. Right column. Each command is announced with a `$`
  prefix before it runs, so the pane reads as a transcript rather than as
  unattributed lines — it is what an administrator pastes into a bug report.
  The command is rendered as the task asked for it, without the `sudo`/`doas`
  wrapper this host resolved, and never carries what was fed on stdin (a
  WireGuard private key travels that way precisely to stay out of view).
  A failed task's error is written here as well as into the status, since the
  status is a single line on a border and a package manager's stderr does not
  fit in it.
  Retains the most recent 5000 lines in a ring buffer, dropping the oldest. The bottom border states whether the view
  is pinned to the newest output (`follow`) or has been scrolled away
  (`detached`), and while following, a `▌` cursor marks where the next line
  will land — a quiet command and a frozen screen otherwise look identical.
- **Detail** — occupies the same area as Output before any task has run,
  showing what the selected task does, titled with the task's own name. With a
  category selected it shows the category name and how many tasks it holds at
  any depth.
- **Status** — the state word plus a message, on the bottom border of whichever
  pane is showing on the right. Costs no rows. Right-aligned, opposite the
  census on the tree and opposite `follow`/`detached` on the output, since two
  bottom titles at the same end are drawn over each other.
- **Key bar** — the key hints for the current row and state. One borderless
  row, dropped on terminals shorter than 24 rows.
- **Parameter form** — overlays the centre of the screen for tasks that collect
  values (a port, a username, a public key). Modal. **A field is two rows and a
  blank one:** a header carrying its label on the left and its verdict on the
  right, the value indented beneath, and a separator before the next field.
  Everything on either row belongs to the field its header opens, which is what
  a boxed field could not say — its note sat as close to the field below as to
  the value it judged, and three of the four rows a box spent were drawing a
  frame around a single line of text. The separator is drawn *between* fields,
  and the block of them is inset from the frame by that same row at each end,
  so the spacing reads as one rhythm rather than as fields crowded against the
  border at both ends. After the last one a **rule** spans the dialog, corner
  to corner, before the footer. A blank row could not say it — blank rows are what separate one field
  from the next, so the same mark would have meant both "another field follows"
  and "the fields end here", and the keys below act on the dialog rather than
  on any one field. The
  focused field is marked by a bar in the gutter left of its label, a column
  reserved whether or not it holds the focus so `Tab` shifts nothing sideways.
  The counter (`field 2 of 3`) rides the top border opposite the title, being
  state of the dialog rather than of a field. The verdict is a `✓` for a field
  holding an acceptable value and says nothing more; words are kept for the two
  states a mark cannot carry — an error, and `optional, may be left empty` for
  a field that is empty and may stay so, whose value reads `(unset)`. A green
  mark over an untouched field said "done" about something nobody had typed
  into. Validation runs on every keystroke, so the consequences of a value are
  visible before `Enter` rather than after — **including what the host already
  says about it**. A field naming an account to create refuses one that exists
  (`root already exists`); a field naming one to act on refuses one that does
  not (`deploy is not an account here`). That is a rule no value's *kind* can
  carry: whether a name is well formed is a property of the text, and whether
  this machine has it is a property of the machine. Shape is reported first,
  since a name holding a `/` is malformed whether or not the account exists.
  The check is silent where the host was never asked — the CLI, or a
  `/etc/passwd` that could not be read — because an empty account list means
  "unknown", not "no accounts"; the task's own check remains the barrier.
  Fields whose values the host already records — usernames, login shells —
  offer them rather than asking the operator to remember; the count shares the
  header's row. **A password field is drawn as bullets**, one per character so
  the operator sees keystrokes landing without the value being readable over a
  shoulder or in a screenshot. Empty is a valid answer there and means "no
  password": a second field asking whether to use the first would be a question
  the first already answers — this tool asked exactly that for a while, in a
  text field taking the word `yes`.
- **Options list** — overlays the form, below it, listing everything the host
  offers for the focused field. Modal over the form: while it is open, all keys
  go to it. Opened with `Ctrl-L`, and only offered where the field has options.
- **Confirmation dialog** — overlays the centre of the screen before **any task
  that changes the machine**. Modal: while it is open, all keys go to it. Sized
  by what it holds, like every other modal: it was a share of the screen
  (60% × 40%), which put a block that size around two lines of text and left
  half of it empty — tolerable while nine tasks confirmed, and not once all but
  three do. It has two forms, and the difference is what keeps either
  worth reading: a change that can end the session applying it is framed in
  red and carries the lockout warning, everything else asks in the ordinary
  frame with no warning at all. Only a task that purely reads opens no dialog
  — `firewall.status`, `wireguard.status`, `caddy.validate`.

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
| `!` | The task can lock me out of the machine |
| `…` | The task collects parameters before it runs |
| `·` | The task is not supported on this host |
| `?` | The row's verb has not been settled yet |

A row carries at most one flag, and they rank in that order: a task that both
risks a lockout and takes parameters shows `!`, since the warning outranks the
notice. `!` marks the lockout tier alone, not every task that confirms —
almost all of them do, and a marker on nearly every row names none of them.

## Rows that change their verb

Some rows hold two opposed operations and show whichever one the host
justifies: `Install Caddy` where Caddy is absent, `Uninstall Caddy` where it is
present. One row rather than two, because exactly one of them is meaningful at
any moment and a tree offering both makes the reader work out which.

What the host holds is measured in the background at startup, and again after a
task finishes — never while one runs, and never in the path of a keystroke. Until
the answer arrives the row shows the *install* verb and carries `?`: offering to
install something already present wastes a keystroke, while offering to remove
something absent is a row that does nothing and explains nothing. The marker is
transient, usually gone within a few hundred milliseconds of startup.

A program found somewhere this tool did not install it — a `zellij` from
`cargo install`, say — leaves the row on its install verb, and the detail pane
names the path that was found. What this tool did not put there is not its to
remove.

Both halves are searchable by name, so `/uninstall` finds a row the tree may be
drawing as `Install`. Search addresses operations; the tree addresses rows.

## Status

One authoritative place for what the tool is doing: the bottom border of the
pane on the right, right-aligned. It reads as up to three parts in a fixed
order — the liveness signals, the state's word, then its message — separated by
`·` and drawn only where each applies:

```
└ VERIFY  ·  ssh.harden — applied, not yet kept ┘
└ ⠿  0:12  ·  RUNNING  ·  installing openssh    ┘
```

The word carries the meaning alone when colour is absent; the colour is
redundant reinforcement rather than the signal.

`READY` is the one state that is **not** named. It is the state the tool is in
whenever it is in no other, so a border reading it for most of a session says
only that the program is running — which the screen already says — and teaches
the eye to skip the one place a failure will appear. Its *message* is still
drawn when it has one (`cancelled` after a stopped task): that is a report, not
a redundancy.

| State | Meaning |
|------|---------|
| — | Waiting for input; nothing is drawn |
| `RUNNING` | A task is running |
| `DONE` | The last task succeeded |
| `FAILED` | The last task failed |
| `CANCELLED` | The last task was interrupted before it finished |
| `VERIFY` | A change is applied but not yet kept |
| `CONFIRM` | A confirmation dialog is open |
| `INPUT` | A parameter form is open, collecting input before the task runs |
| `UNSUPPORTED` | The selected task cannot run on this host |

**Every word in this document's tables is the English rendering.** All
user-facing text — these state words, the key bar's labels, the help overlay, the
verification banner — is resolved through the message catalogue against the
locale in the environment (`LC_ALL` > `LC_MESSAGES` > `LANG`, falling back to
English). English is the only catalogue that exists today, so what is tabulated
here is what every host shows; a second language would change the words without
changing anything else in this document. Two kinds of string stay out of the
catalogue deliberately, being not words in a language: key glyphs (`Tab`, `↑ k`)
and drawing symbols (`│`, `✓`), and the tasks' own ids, titles and descriptions.

A test that reads the screen is therefore locale-sensitive by construction and
must pin `LC_ALL`, rather than relying on the developer's environment happening
to be English.

Three of these describe the cursor rather than the past and therefore override
whatever the last action left behind: `CONFIRM` while a dialog is open, `INPUT`
while a form is, and `UNSUPPORTED` when the selected row cannot run here. The
state must always say what pressing `Enter` would do now.

`CONFIRM` outranks `INPUT` where both apply: a task that confirms collects its
parameters first and confirms after, so once the confirmation is up it is the
live question.

### Transient messages

Refusals — "already at the top level", "not supported on arch" — flash beside
the state's word for two seconds and then disappear on their own. They override
the state's message but **never** its word: losing sight of what the tool is
doing because something was refused is exactly what the separation prevents.

There are no toasts and no overlays. A message that occludes content is
unacceptable when the content is the log of a command running as root.

### When the border runs out of room

A border is narrower than a row was, so two rules decide what goes first, and
both protect the state's word:

- **The message is truncated, never the word.** It loses its tail to a `…`;
  below eight cells it is dropped whole instead, since what survives at that
  width is a smear rather than a shortened sentence.
- **The pane's own indicator yields the border entirely** where the two would
  not both fit — the tree's census, the output pane's `following`/`detached`.
  Neither is the only place its information appears: the census counts rows
  already on screen, and whether the view is pinned is also visible from the
  write cursor and from whether the log is moving. The status may be the only
  report of a task that failed.

  Opposite ends is not enough on its own. Ratatui draws two bottom titles that
  outgrow the border rather than arbitrating between them, which rendered the
  census as `6 ca FAILED …` and `following` as `f`.

Below 72 columns only one pane is drawn, and the status follows it: with focus
on the tree it rides the tree's border, so pressing `Tab` back after a failure
never hides the report of it.

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
| `block_subtitle` | White + dim | Category counts, separators, and the `?` marker |
| `result_ok` | Green | The `✓` glyph, `ok` lines, and a form field's verdict |
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
| `badge_busy` | Black on yellow + bold | The `VERIFY` badge in the verification banner |
| `status_ready` | Green + bold | `READY` and `DONE` on the pane border |
| `status_busy` | Yellow + bold | `RUNNING` and `VERIFY` on the pane border |
| `status_error` | Red + bold | `FAILED`, `CANCELLED` and `CONFIRM` on the pane border |
| `status_input` | Blue + bold | `INPUT` on the pane border |
| `status_inert` | White + dim | `UNSUPPORTED` on the pane border |
| `keybar_key` | Reset + bold | The key glyph in the key bar |
| `keybar_label` | White + dim | Its description |
| `gauge` | Green | The step-progress gauge |

The `status_*` roles set a foreground only, unlike the badge above them. They
are drawn on a pane's bottom border, where a background fills the cells the
border runs through and reads as a gap in the frame rather than as emphasis.
`badge_busy` keeps its pair because the verification banner is a block of its
own rather than a border it has to sit inside.

`selection_focused` sets an explicit foreground/background pair rather than
reversing: reversal swaps per cell, so a red lockout marker on a reversed
row would render as a red block and the row's meaning would invert with it.

`selection_disabled` is drawn on the selected row when the task under it cannot
run on this host. The ordinary blue cursor reads as "press Enter", and pressing
it there does nothing — which looks like the interface dropping the key rather
than the host refusing the task. Colour is not carrying that alone: the same row
already shows `·` in its flag column.

Three roles are still declared and never drawn — the gauge, the result glyphs
(`result_fail`, and `result_ok` outside the form's own summary line), and the
tree's depth guides. They are declared here and in source so the table stays one
readable reference, and so a new call site picks a role instead of inventing a
colour. `search_match` was one of these until search was built, and
`selection_disabled` until the tree began drawing it; both are drawn now, which
is what the list is for.

`gauge` is the substantive one left: it implies a progress element with a real
design question behind it, since a task's command count is not known before it
runs. `tree_guide` and `result_fail` are small, and waiting on a place to put
them rather than on a decision.

A role that is declared and never drawn is a promise this document has not yet
kept, so the list is deliberately explicit rather than left to be discovered by
grepping for unused constants. The reverse also has to be maintained by hand:
`border_unfocused` sat in this list while being drawn on every unfocused pane,
because it reaches the screen through the `border(focused)` helper rather than
by name, and a grep for the constant found nothing.

## Keys

### Anywhere

| Key | Action |
|-----|--------|
| `Tab` | Move focus between the tree and the output |
| `?` | Open the help overlay |
| `q` | Quit, from any level and either pane |

The arrows mean "next" and "previous" in both panes, so something has to say
which one they address. That something is `Tab` and **nothing else**:
overloading a movement key with focus is how keys start leaking between panes.

The focused pane is drawn with a cyan border; the other is dim. The tree's
selected row stays visible when focus leaves it, drawn underlined rather than
highlighted — losing the cursor on `Tab` would mean hunting for it again on the
way back.

### Task tree

| Key | Action |
|-----|--------|
| `↑` | Move to the previous row (categories included) |
| `↓` | Move to the next row |
| `Home` / `End` | Jump to the first / last row of the level |
| `Enter` | Open the selected category, or run the selected task; anything that changes the machine opens the dialog first |
| `/` | Open search over the whole tree |
| `h` | Open the recorded changes, with any one restorable |
| `Esc` / `Backspace` / `←` | Go back to the parent level; at the top level it reports rather than quitting |

Every row is selectable: a category that could not be selected could not be
opened. `Esc` means "go back" rather than "quit", so pressing it one level too
many cannot drop the user out of the program — `q` is the only way out.

A scrollbar appears on the right edge of the tree only when the level overflows
the pane; a track drawn against a level that fits is a permanent hint that
content is hidden when none is.

### Search (semi-modal)

Opened with `/` from the tree. Twenty-eight tasks across six areas is past the
number anybody keeps a map of, and drilling down one level at a time answers
"what is in here" rather than "where is it" — without this the only recourse
was `docs/cli.md`, outside the tool and possibly not on the server.

| Key | Action |
|-----|--------|
| (any printable character) | Append to the query; `/` included, since a query is literal |
| `↑` / `↓` | Move between results; stops at the ends rather than wrapping |
| `Enter` | Move the tree cursor to that task, without running it |
| `Backspace` | Delete a character; on an empty query, close the search |
| `Esc` | Close, leaving the tree cursor where it was |

Matching spans the **whole tree**, not the level on screen, and covers both the
title and the task id — `docs/cli.md` and any script name the id, while somebody
who has only used the interface knows the title. It is case-insensitive, and
the matched span of a title is highlighted (`search_match`) so a row does not
look like an unexplained hit. Each result carries its breadcrumb and id, since
a title alone does not say which area it came from. An empty query matches
everything, which makes opening search the one view listing every task with its
area beside it.

`Enter` navigates rather than runs. The task is then started from the tree like
any other, so a result goes through the same confirmation and the same
parameter form; a path that skipped either would make a mistyped query the most
dangerous key in the interface.

Search is refused while a task is running or a change is unverified, for the
same reason `Enter` is: only one task at a time.

### Output pane

| Key | Action |
|-----|--------|
| `↑` | Scroll one line towards older output, detaching from the tail |
| `↓` | Scroll one line back towards the newest |
| `PageUp` / `PageDown` | Scroll by ten lines |
| `Home` | Jump to the oldest retained line |
| `End` / `f` | Jump to the newest output and follow it again |
| `y` | Send the whole transcript to the terminal's clipboard |

Any upward scroll detaches the view from the tail, so reading back through a
log is never interrupted by new arrivals. Scrolling back to the bottom
re-attaches on its own — the operator has caught up, and needing another key to
resume following would be a step with no purpose.

**The pane moves the view and hands over the transcript; it does nothing else.**
It is a record of what a task did, and a record is read rather than operated.
`w` toggled wrapping and `Esc` returned focus, and both were bindings to
remember in front of no decision they helped make — the wrap now stays on, so
no line is ever cut at the right edge, and `Tab` is the one key that moves
focus anywhere in this interface. Long lines are the case wrapping exists for:
a package manager's error is exactly the line that outruns the pane, and it is
the line the operator is there to read.

**Focus is never moved here by the tool.** Running a task used to move it, on
the grounds that reading what is about to happen is the natural next thing —
true of the pane, which streams either way, and not of the cursor. What it
actually did was take the arrow keys off the tree, so moving on to the next
task meant pressing `Tab` first to undo something nobody asked for. `Tab` is
the only thing that moves focus.

#### Copying the transcript

`y` sends every retained line to the terminal's clipboard as an OSC 52
sequence. It exists because **the mouse cannot do this**: the terminal owns the
selection and copies rectangles of screen, so dragging over the pane takes its
border and the tree's flags with it, and takes only what the pane was wide
enough to draw — every line longer than the pane arrives cut. `initd` cannot
restrict that; capturing the mouse would disable the terminal's own selection
and replace it with nothing.

- **Whole lines, both streams, in arrival order.** Dropping stderr would lose
  the error the transcript is usually being copied for.
- **OSC 52 rather than a clipboard library or `xclip`.** The machine being
  administered usually has no display server, and its clipboard would be the
  wrong one anyway — the operator is at the other end of an SSH connection.
  The sequence asks the *terminal* to set the clipboard, so it travels through
  SSH and tmux.
- **The message says what was sent, never that it was copied.** OSC 52 has no
  reply, and terminals that refuse it are real — some ship with it disabled,
  since a program that can write the clipboard can also overwrite it. Claiming
  success the tool cannot observe is how a message stops being believed.

### The key bar

The hints follow the focused pane and the row under the cursor rather than
listing every binding: a bar that never changes is one the operator stops
reading. On the tree the `Enter` hint reads *open* on a category and *run* on a
task; `Esc back` appears only below the top level, and `Tab output` only once
there is output to switch to.

`h history` is offered unconditionally, where those two are not. The difference
is what an empty one leads to: `Tab` with nothing to read opens a mute pane,
while `h` on a host where nothing was recorded answers the question it was
pressed to ask — *has this tool changed anything here* — and *no* is an answer.
Testing it first would also mean reading the host's index to draw a frame.

Where the row is too narrow for every hint, hints are dropped rather than
truncated — the bar does not wrap, so anything past the edge is simply lost, and
what sits at the edge is `q quit`. They are given up least-useful-first —
`Tab output`, then `h history`, then `/ find`, then `Esc back` — ordered by how
discoverable each key is elsewhere rather than by how often it is pressed:
`?` documents all of them and the header points at `?`, while leaving a category
has no route but `Esc`. `↑↓`, `Enter` and `q` are never dropped.

### Parameter form (modal)

Every printable character is **literal** here — `h`, `q` and `/` type
themselves rather than acting as commands. Only the keys below stay commands.

| Key | Action |
|-----|--------|
| `Tab` / `Shift-Tab` | Next or previous field, always |
| `↓` / `↑` | Step through what the host offers, where it offers any; move between fields where it does not |
| `Ctrl-L` | Open the full list of what the host offers, where it offers any |
| `Enter` | Next field, or submit on the last one |
| `←` / `→` | Move the cursor |
| `Home` / `End` / `Ctrl-A` / `Ctrl-E` | Jump to the start or end of the value |
| `Backspace` / `Delete` | Delete before or under the cursor |
| `Ctrl-U` / `Ctrl-K` | Clear before or after the cursor |
| `Ctrl-W` | Delete the previous word (readline's convention wins here) |
| `Esc` | Cancel |

`Tab` keeps moving between fields unconditionally, which is what makes the
overloading of `↑↓` safe: a field with options is still left with a key that
does nothing else, and the footer names it.

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

#### Values the host already knows

Some fields are filled from the host rather than from memory:

| Field | Source | Order |
|-------|--------|-------|
| An account that must already exist | `/etc/passwd` | `root`, then the accounts a person logs in as, then the system ones — each group alphabetical |
| A login shell | `/etc/shells` | As the file lists them, comments and blank lines dropped |
| A release version | This build's own table of verified releases | Newest first, so the field opens on the most recent one |

The last of those asks the host nothing, and cannot: the digest that makes a
download trustworthy is compiled into the binary, so the releases it can verify
are known before the machine is. That is also why the field does not offer
whatever upstream published this morning — a version with no compiled-in digest
is one the task refuses, and suggesting it would be proposing the refusal.

**Each field declares its own source; none is inferred from the field's type.**
A field's type describes the shape of a value, and what the host can offer for
it depends on the value's relation to the system — the two come apart in both
directions. `users.create` collects a username that must **not** exist, so
offering the host's accounts there suggests precisely the values it refuses.
`wireguard.add-peer` collects a peer *label* validated by the username rules
because they suit it, and the host has nothing to say about it. Both are the
same type as the account field of `ssh.authorize-key`, which does want them.

`ssh.allow-users` names existing accounts and still offers nothing: it holds a
space-separated *list*, and taking a suggestion replaces the whole value, so
each choice would delete the names already typed. Completing within a list is a
different mechanism from choosing a value.

A field with no source offers nothing and says nothing — no count beside it,
and no `Ctrl-L` in the footer. A key named in a footer and doing nothing is
worse than one that was never offered.

An account is **ordered down, never hidden**: `www-data` owns a home a key can
be installed into, so refusing to offer it would leave the form rejecting what
the system accepts. But a stock Debian carries forty service accounts and two
of the other kind, and a chooser that opens on `_apt` is one nobody reads to
the end.

These are **suggestions, never the permitted set** — with one exception, and
the exception is what makes the rule worth stating. Every host-sourced field
stays typeable, because the host's answer can be incomplete: an account can be
created between one form opening and the next, and a shell absent from
`/etc/shells` is still a path. Validation is unchanged and remains the only
thing that decides.

A **closed choice** is the other case. `remove`/`purge`, `tcp`/`udp` and
`keep`/`delete` are not what the host happens to hold but every value the
validator will accept, so the list is the permitted set.

The removal depth is also **not drawn where this host has no depth to choose**.
It decides whether configuration survives, and it decides that through a
package manager — so where a capability is not a package on this family (Zellij
and Caddy on Debian arrive as verified release binaries) the undo deletes a
file and both words name the same `rm`. RHEL is the same shape for a different
reason, rpm having no purge at all. A form whose only field is filtered out
this way opens no form: the confirmation follows the keypress directly, which
is also what `users.lock-root` now does — for the opposite reason, having no
fields to filter. It asked which account keeps access and did nothing with the
answer but check it, so it reads the host instead and shows what it found. The CLI
still takes `removal=` on those hosts and reports that it could not be
honoured, because a script written against a host that packages the capability
should not quietly mean something weaker on one that does not. They were typed by
hand until they were not: the field was a blank with a hint underneath naming
two words, which asked the operator to read the hint and then spell one of them
correctly on a choice — in the removal's case — that decides whether a
hand-edited config file survives. The field still accepts typing, because a
list that also blocked the keyboard would be a different widget for no gain,
and two tests keep the offered values and the validator from drifting apart:
one asserts every offered value passes the validator, the other that every kind
with a closed validator offers a list at all.

The count rides the field's header (`↑↓ 2/6 on this host`), left of the
verdict, rather than taking a row of its own; on a three-field form a row each
is the difference between fitting a 24-row terminal and not. It reads `↑↓ 6 on this host` with no
position while the value is not one of the options — typed by hand, or not yet
typed.

The values are resolved **once, when the form opens**, and once per kind rather
than once per field: running `cat /etc/passwd` on every arrow press would put
the executor in the path of a keystroke. Two sources ask the host nothing — the
verifiable releases and the closed choices are both compiled in — so they are
answered without a command and cannot fail to resolve. A host whose file cannot be read
offers nothing and says nothing — the field behaves as it did before there was
anything to offer, since refusing to open the form would turn a convenience
into a prerequisite.

#### Options list (modal over the form)

`Ctrl-L` opens everything the focused field offers. Stepping with `↑↓` suits
the three shells `/etc/shells` usually holds; forty accounts is not a list you
read one press at a time.

| Key | Action |
|-----|--------|
| `↓` / `↑` | Move through the list, wrapping at both ends |
| `Home` / `End` | First or last option |
| `Enter` | Take the option and close |
| `Esc` | Close, leaving the field exactly as it was |

Drawn **below the form**, keeping its width and left edge so the two read as
one stack — centred, it landed on the very field it answers. It goes above
instead when there is more room there, and is **shrunk to whatever that side
has** rather than merely moved: at full height where the room is shorter it
runs through the frame's bottom border and reads as having broken the
interface. The list scrolls, so fewer rows means fewer visible at once rather
than options that cannot be reached.

Moving the cursor here is reading the list, not answering it: nothing is
written to the field until `Enter`.

### Help overlay

| Key | Action |
|-----|--------|
| `↑` / `↓` | Scroll a line |
| `PageUp` / `PageDown` | Scroll a page |
| `Home` | Top of the list |
| `End` | Bottom of the list |
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

The status opens with two liveness signals while a task runs: a one-character
ASCII spinner and a wall-clock timer, both driven by the clock rather than by
arriving output. Over a slow link a quiet command and a frozen screen are
otherwise indistinguishable. They lead rather than trail so they sit at a fixed
distance from the pane's corner while the message beside them changes length.
The spinner is ASCII rather than braille, which is missing or double-width in
too many of the fonts a server console actually has.

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

`K` and `R` are **uppercase deliberately**. They were capitals because `k` was
"move up" everywhere else, and they stay capitals now that it means nothing:
this is the one window where a key pressed by accident does something
unrecoverable, so answering it should cost a deliberate `Shift` rather than a
letter that could be a slip.

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
| `↑` / `↓` / `k` / `j` | Scroll the warning, where it has more than it shows |
| `y` | Apply |
| `n` / `Esc` | Cancel |
| `Enter` | Confirm the current answer |

The dialog opens on **No**, so a stray `Enter` cannot start a change. `n` and `Esc` both mean the safe answer, so the reflex to back out
lands on it whichever key it reaches for.

The warning scrolls because one of them carries a list rather than a sentence:
`users.lock-root` names every account that keeps access, which is unbounded —
one row per administrator the host has. A dialog sized to all of them would
grow past the terminal, where centring clamps it and the answers at the bottom
are what disappear. So the band is capped and scrolls instead, and the scroll
hint appears only on a dialog that has rows below the fold: a key hint for a
key that moves nothing is how a bar stops being read.

## Running a privileged task

The password is asked for **once, before the interface starts**, while the
terminal is still ordinary and `sudo` can draw its own prompt. `initd` never
reads it: the prompt belongs to sudo, and what the tool gets is the
authentication timestamp sudo leaves behind. Later privileged commands reuse
that timestamp, which is what lets a task's output stream into the pane instead
of the interface being torn down and rebuilt around every command.

Two properties this depends on, measured on real Debian 13 and Arch systems
with the probes in `tests/fixtures/validate-sudo-*.sh`:

- Both key the timestamp by **terminal**, so spawned commands inherit stdin
  rather than being given `/dev/null` — a process with no terminal is refused
  even when the session that spawned it has authenticated.
- Arch expires it after **five minutes**, not the fifteen usually assumed. Any
  privileged command extends the window, so a task in progress keeps it open.

A refusal at startup is not fatal. The operator may have cancelled the prompt,
or the mechanism may not support this at all — `doas` has no equivalent and
`run0` defers to polkit — and privileged commands still work either way. They
simply prompt when they run.
