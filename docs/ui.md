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
│ └ census ────────────┴─────────────────────────────┘│
├────────────────────────────────────────────────────┤
│ Key bar                                       1 row│
└────────────────────────────────────────────────────┘
```

Nothing is drawn on the bottom border except the tree's census. There is no
status line: what the tool is doing is said by what is on screen — a dialog or
a form occupies the middle of it, an unsupported row is dimmed and flagged —
and what a task *did* is reported in the output pane, beside the commands that
produced it. See *Failure reports*.

What went with it were the spinner and wall-clock timer that distinguished a
quiet command from a session that had stopped answering. For a while nothing
replaced them and the output pane's write cursor was the whole signal, which
neither moves nor counts. Both are back in the header while a task runs, where
they cost no rows and can name the task as well — see *What the interface says it
is doing*.

The body's split follows the terminal width:

| Width | Split |
|-------|-------|
| ≥ 100 columns | Tree fixed at 50 columns; the right pane absorbs the rest |
| 72–99 columns | Tree 42%, right pane 58% |
| < 72 columns | One pane at a time |

The tree takes a fixed width above 100 columns because its content has a
natural one, so extra width belongs to the output, where lines are long and
wrapping hurts. Giving the tree a share of a wide terminal would spend it on
padding.

**That width is measured, not chosen.** The longest task title is 44 cells and
a row spends six more — two of border, two of marker, one of flag, and the
space separating the title from it — so 50 is the width at which no task in
the tree is truncated. (46 is a different constant: the *minimum* the right
pane is promised, which a compile-time assertion ties to this one.) A task added with a longer name shortens the others,
silently: a truncated title still renders, it just cannot be read. A test
compares the constant against the tree so that the day it stops being true is
a failing build rather than a screen nobody can use.

Below 72 columns the two panes become **two views of one area**, switched with
`Tab`. The header trades the host facts for a `tasks / output` indicator, since
nothing else would say which of the two is showing and `Tab` would look like it
did nothing.

The key bar is dropped below 24 rows — it is a convenience, and it is the only
band that can be given up at all.
Below **60 × 15** the interface is not drawn at all: it states the size it needs
instead, because a garbled layout on a production server is worse than a clear
refusal.

## Modals

The six dialogs — confirmation, parameter form, ports table, help overlay,
search, recorded changes — are drawn to one set of rules, so a frame does not
move for reasons the operator cannot name:

| Rule | Value |
|------|-------|
| Width | 72 columns, clamped to the terminal — except the ports table, at 88 |
| Height | measured from the content; never a share of the screen |
| Gutter | 2 cells between the frame and any text |
| Inset | one blank row at each end of the content |
| Footer | on the bottom border, or above it behind a rule where the content runs to the frame |

The ports table is the one dialog wider than 72, and the exception is about
what it holds rather than about taste. The shared width is a *floor* set by the
parameter form's footer, and every other dialog's content is prose, which reads
worse the wider it gets. A table is the opposite: its columns need room to be
columns rather than words that happen to line up, and its third column carries
a service name beside them.

The footer has two spellings and the difference is what the content needs
rather than taste: the confirmation and the parameter form draw a rule because
their content reaches the bottom of the frame and a footer against it would
read as part of the text, while the four whose content stops short — the ports
table among them — ride the border itself. Either way the keys are drawn, which
is the part that matters.

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
the copy is damaged — reports into the output pane under a `COULD NOT RESTORE`
heading, with the two digests that disagree as fields. That heading is deliberate:
the refusals leave the machine exactly as it was, which is a different thing from
a command that broke.

## Panels

- **Header** — the product name and version, the machine's hostname, the
  detected distribution, and how root is obtained (`root via sudo`). One
  borderless row. The hostname is emphasised because it answers the question an
  administrator with several terminals open actually has — *which machine am I
  about to change?* — and the privilege mechanism is stated up front so that
  "this will need a password" is known before a task is started rather than
  when one fails. A `? help` hint is right-aligned when the width allows, and
  dropped rather than wrapped when it does not.

  **While a task runs it says so instead.** The distribution and the privilege
  mechanism give way to a turning throbber, the running task's id and an elapsed
  `m:ss`; the name and hostname stay, and the two facts come back when the task
  ends. They are the right ones to spend: neither changes, and what is happening
  now is the more urgent question. Below 72 columns the header shows the
  `tasks / output` indicator instead, since nothing else would say which pane
  `Tab` is showing.
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
  A failed task's error is written here and **only** here. See *Failure
  reports*.
  Retains the most recent 5000 lines in a ring buffer, dropping the oldest.
  While the view is pinned to the newest output a `▌` cursor marks where the
  next line will land; scrolling away detaches, and the cursor's absence is
  what says so. A finishing task jumps the view back to the tail, so its report
  is on screen even where a chatty task wrote more lines than the pane is tall.
  Escape sequences are stripped from what a command prints, so a script that
  colours unconditionally does not put raw `\x1b[` codes on the screen or into
  the transcript.
- **Detail** — shows what the selected task does, titled with the task's own
  name. A task whose stated precondition this host does not meet says so
  here — *"Not ready yet: run firewall.enable first."* — below its description
  and in the same shape as a refusal by family, because the two answer the same
  question: why pressing `Enter` will not do what the row offers. They differ
  only in whether the operator can fix it, which is why one names a task and the
  other names a distribution.

  **The row refuses `Enter` as well as saying why.** It is dimmed and carries
  `-` in the flag column, exactly as a task the distribution cannot run is
  dimmed and carries `·`: both are rows the key declines, and the detail pane is
  what tells them apart. The key bar drops its `Enter` hint there rather than
  promising an action the row will decline.

  That marker outranks `!`, which looks wrong and is not. `!` warns that acting
  on the row could end the session; a row whose precondition is unmet will not
  act at all, so the warning describes something that cannot happen while the
  marker describes why the key does nothing.

  Saying so without refusing was the first version, and it was worse than
  either: `firewall.manage-ports` still collected a set of ports and still
  opened its red lockout dialog before the guard inside the task refused —
  a sequence of decisions spent on an outcome that was never available.

  Nine tasks declare one today: `firewall.manage-ports` needs a policy, the four
  that edit `sshd_config` need an SSH server, and `wireguard.add-peer`,
  `docker.rootless`, `caddy.validate` and `caddy.security-headers` each need the
  thing they configure.

  **Silent until measured, and pressable until measured.** The check runs on the
  same background probe as the install/uninstall verbs, which has no privilege
  escalation by design — it must never raise a password prompt over somebody
  reading the tree — so a check it could not run is an ordinary outcome rather
  than an edge case. That state says nothing and refuses nothing: a row greyed
  out on the strength of a question nobody managed to ask is one the operator
  can neither run nor explain. The task's own guard is still there, and it asks
  the host at the moment it would act rather than reporting what was last
  measured. With a category selected it shows the category name and how many tasks
  it holds at any depth.

  It **shares the right-hand pane with Output**, description above and
  transcript below, taking up to seven rows and leaving the rest to the
  output. A ceiling rather than a share, because a description is a sentence or
  two of known length while a transcript grows: splitting by percentage would
  leave half the pane blank above a log that is scrolling.

  Before this the pane showed one or the other, chosen by whether any output
  existed — so once a task had run, every task selected afterwards had its
  description displaced by the previous one's transcript, with no way back
  until another task started.

  Two exceptions. Below 18 rows of pane the output takes it whole, since
  splitting serves neither half; and `o` folds the *description* away, giving
  the output the pane, for when a long transcript is worth all of it. The
  description is the half that yields: it is static text about a task already
  running, while the transcript is what is being watched.
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
  applies, and a legend for the row markers. Opened with `?` from anywhere,
  including on top of a dialog, since the moment someone needs the key list is
  the moment they do not know which key to press. Scrollable, because the
  section worth reading most — the keys that cannot be guessed from anywhere
  else — is the one at the end.

  **The marker legend is the one section that is not keys**, and it is there
  because a flag is the only thing on screen carrying meaning with no word
  beside it. Every other glyph either names a key the operator pressed or sits
  next to text explaining it; `!`, `…`, `·`, `•` and `?` sit alone in a column.
  So they were the only thing an operator could see and have no way to look up
  from inside the tool — this file had the table, and this file is not on the
  server. Each is drawn in the colour it has on the row, because someone asking
  about a red `!` is asking about the colour as much as the glyph.
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
| `·` | The task is not supported on this host |
| `-` | The task is supported, and something must run before it — the detail pane names what |
| `!` | The task can lock me out of the machine |
| `…` | The task collects parameters before it runs |
| `?` | The row's verb has not been settled yet |
| `•` | The subject was already here before this session — the row offers to install something the host already has, and has no inverse verb to switch to instead |

A row carries at most one flag, and they rank in that order: a task that both
risks a lockout and takes parameters shows `!`, since the warning outranks the
notice. `!` marks the lockout tier alone, not every task that confirms —
almost all of them do, and a marker on nearly every row names none of them.

The two that refuse the key come first, which is the ordering worth explaining.
A row the distribution cannot run and a row waiting on another task are both
rows `Enter` declines, so what they carry has to say *that* before it says
anything about what the task would have done. `firewall.manage-ports` on a host
with no policy shows `-` rather than `!`: the lockout warning describes a risk
of acting, and the row will not act.

**The five flags are also listed in the help overlay**, in the colours they are
drawn in, so this table is not the only place they are explained. It was, and
that is a poor place for it: a glyph is exactly the thing an operator can see
and not know, and the answer sat in a file that is not on the server being
administered. `›` is left out of the legend — it opens a level, which pressing
`Enter` or `→` on it demonstrates faster than a line of text. A test asserts
every marker the tree draws appears there, so one added here and forgotten
fails the build rather than shipping unexplained.

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

## What the interface says it is doing

There is no status line. What the tool is doing is said by what is on screen,
and what a task *did* is said by the output pane.

| Situation | How it is shown |
|-----------|-----------------|
| A task is running | The header names it beside a turning throbber and the time it has run; the output pane streams its lines, `▌` marking where the next lands |
| A stop has been asked for | The key bar drops `Ctrl-C stop` for `stopping after this command` |
| A task succeeded | Its output, and any consequences it declared, in the pane |
| A task failed | A `FAILED` block in the pane — see *Failure reports* |
| A task was stopped | A `STOPPED` block naming the command it stopped before |
| A change is applied, not yet kept | The verification banner, with its countdown and both keys |
| A confirmation is open | The dialog itself, centred and modal |
| A form is collecting values | The form itself, centred and modal |
| A first `Esc` has armed a discard | The dialog's `Esc` hint reads `again to discard` |
| The selected task cannot run here | The row is dimmed and flagged; the detail pane says why |

**The header answers "is anything happening" while a task runs.** It trades the
distribution and the privilege mechanism — two facts that do not change, and
both back the moment the task ends — for a throbber, the task's id, and an
elapsed `m:ss`. Before this the only sign of life was the output pane's write
cursor, which neither moves nor counts, so a command that is merely slow (an
`apt-get` resolving mirrors over a laggy link) was indistinguishable from a
session that had stopped answering. The reflex that follows is closing the
terminal, and closing the terminal raises `SIGHUP` — which reverts an unrelated
unkept change. The id is there for the same reason the hostname is: it answers
*what* is running, not only *that* something is.

The count is elapsed time rather than progress. A task's command count is not
known before it runs, so a percentage would be invented, and the throbber is
indexed off elapsed time rather than a counter — the event loop already redraws
on a timeout it has, so the animation costs no extra wakeups and no state. The
words beside it carry the meaning either way, so a terminal without the braille
glyphs loses nothing.

**A stop that has been asked for is acknowledged.** Cancellation is refused
between commands rather than interrupting the one in flight, so a task mid-`dnf`
can absorb a minute before anything else changes. For that minute the screen was
byte-identical to before the keypress and still advertised the key — so the
keypress read as dropped, and pressing it again is silently ignored. The label
says `stopping after this command` rather than `stopping`, which would read as
"killed": the command in flight is still changing the machine.

**What this gives up.** A refusal that answers a keystroke — pressing `Enter` on
an unsupported row, `q` while a task runs — produces no message. The screen
does not change, which is indistinguishable from a key that never arrived. The
dimmed row and its flag are what remain for the unsupported case; the others say
nothing at all. Accepted deliberately: a word in the corner describing a dialog
that occupies the middle of the screen was the larger cost.

Two keys are **not** covered by that, and the difference is what the silence
costs. `Ctrl-C` during a task and the first `Esc` over a dialog holding typed
values are both *accepted* rather than refused — they change state and then wait,
so a screen that does not move reports the opposite of what happened. Worse, the
reflex each one invites is pressing the same key again, and for `Esc` the second
press is what discards the work: an invisible guard turns a one-press loss into a
two-press loss instead of preventing one. Both now say what they did. The rule
this leaves is narrower than "acknowledge every key": a key that changed
something says so, a key that was refused need not.

**Every word in this document's tables is the English rendering.** All
user-facing text — the key bar's labels, the help overlay, the verification
banner, the failure blocks — is resolved through the message catalogue against
the locale in the environment (`LC_ALL` > `LC_MESSAGES` > `LANG`, falling back to
English). English is the only catalogue that exists today, so what is tabulated
here is what every host shows; a second language would change the words without
changing anything else in this document. Two kinds of string stay out of the
catalogue deliberately, being not words in a language: key glyphs (`Tab`, `↑ k`)
and drawing symbols (`│`, `✓`), and the tasks' own ids, titles and descriptions.

A test that reads the screen is therefore locale-sensitive by construction and
must pin `LC_ALL`, rather than relying on the developer's environment happening
to be English.

## Failure reports

A failure is reported in the output pane, which is the only place it is
reported. It is written as a heading naming the task, then one row per field of
the error:

```
$ systemctl --user disable docker.service
Failed to disable unit: Unit docker.service not loaded.

FAILED — docker.rootless-off
command       systemctl --user disable docker.service
exit code     5
stderr        Failed to disable unit: Unit docker.service not
              loaded.
```

Three headings, distinguished because they call for different actions:
`FAILED` (the task broke — diagnose it), `STOPPED` (interrupted — naming the
command it stopped *before*, so what ran and what did not is legible) and
`COULD NOT RESTORE` (a revert failed, so the machine is in neither state).

- **Fields, not a sentence.** An error carries structured values, and a
  `command`/`exit code`/`stderr` flattened into one line buries the exit code
  mid-sentence and loses the stderr to truncation. Errors whose whole content
  is a sentence with no value in it keep that sentence: a heading over an empty
  column would report less than the line it replaced.
- **Continuations hang under the value**, not at the left margin, so a wrapped
  path is not mistaken for another label. Below a readable minimum width the
  indent is dropped rather than squeezing the value into a few cells.
- **Copyable.** The block is part of the transcript `y` copies, whole
  lines rather than the truncated window on screen.
- **A blank line precedes the heading**, so the report reads as separate from
  the command output above it.

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
| `keybar_key` | Reset + bold | The key glyph in the key bar |
| `keybar_label` | White + dim | Its description |
| `gauge` | Green | The step-progress gauge |

`badge_busy` is the one place a word is drawn on a filled background, and it
keeps its pair because the verification banner is a block of its
own rather than a border it has to sit inside.

`selection_focused` sets an explicit foreground/background pair rather than
reversing: reversal swaps per cell, so a red lockout marker on a reversed
row would render as a red block and the row's meaning would invert with it.

`selection_disabled` is drawn on the selected row when the task under it cannot
run on this host. The ordinary blue cursor reads as "press Enter", and pressing
it there does nothing — which looks like the interface dropping the key rather
than the host refusing the task. Colour is not carrying that alone: the same row
already shows `·` in its flag column.

Five entries are still declared and never drawn — `gauge`, `result_fail`, and
the `marker_ok`, `marker_fail` and `marker_cursor` glyphs. They are declared
here and in source so the table stays one readable reference, and so a new call
site picks a role instead of inventing a colour. `search_match` was one of these
until search was built, `selection_disabled` until the tree began drawing it,
and `tree_guide` and `result_ok` since this paragraph last named them as
undrawn; all four are drawn now, which is what the list is for — and why the
list has to be re-derived rather than remembered.

`gauge` is the substantive one left: it implies a progress element with a real
design question behind it, since a task's command count is not known before it
runs. That is why the running indicator counts *elapsed time* instead — seconds
are measured where a percentage would be invented. The one place a gauge would be
honest is the verification window, whose denominator is known exactly; it is not
drawn there either, because the countdown already states the same number in
words. `result_fail` and the three markers are small, and waiting on a place to
put them rather than on a decision.

`consequence` and `consequence_external` were a fourth case, and a worse one:
this table described them and nothing drew them. A consequence rides an ordinary
`Stdout` line, and the pane took its colour from the stream, so both were drawn
in `normal` and the distinction survived only in the glyph — the one thing the
role exists to reinforce. A line now carries an optional *emphasis* saying what
it is, which the pane resolves to a role; the enum lives beside `Stream` in
`exec` and names the kind of line rather than a colour, so the command line
keeps ignoring it. They are drawn as described above.

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
| `o` | Fold the task description away, giving the whole right pane to the output — and back. Offered only once there is output. Nothing is discarded either way: the description is redrawn from the selected task, the transcript is untouched, and focus is left alone because the output stays drawn in both states |
| `Ctrl-L` | Repaint every cell — except in a form, where it opens the field's list |
| `?` | Open the help overlay, over whatever is on screen — including a dialog, the verification window and the recorded changes |
| `q` | Quit, from any level and either pane |
| *(paste)* | Pasted text goes into the field being edited, and is dropped anywhere else |

**`?` means anywhere, including the three states that most need it.** The overlay
draws *over* what it was opened on top of rather than instead of it, which is why
it can be asked for from a modal at all. It was unreachable from the confirmation
dialog, the verification window and the recorded changes for as long as those
handlers ignored the key — the dialog that is about to change the machine, the
window with a timer running whose two answers are capitals, and the view whose
`Enter` restores a configuration file. The states with the least room for a wrong
guess were the three that could not ask.

**Pasting is a distinct event, not a run of keystrokes.** Bracketed paste is
enabled at startup and disabled on exit, so a paste arrives whole. Without it the
text arrives one key at a time and a trailing newline lands on the form's `Enter`
arm — so pasting a public key, which is how a key is entered far more often than
it is typed, submitted the form on whatever had arrived so far, and on a
multi-field form the remainder went into the wrong field. The text is inserted
through the field itself, so what a value accepts decides what survives: the
newline is filtered where every other character is, rather than being special-cased.
Outside a field a paste is discarded — the tree and the output pane act on keys,
and replaying a paste's characters there would run whatever they happen to be
bound to. A terminal that does not understand the request simply never sends the
event, and the old path still works.

The arrows mean "next" and "previous" in both panes, so something has to say
which one they address. That something is `Tab` and **nothing else**:
overloading a movement key with focus is how keys start leaking between panes.

**`Ctrl-L` exists because this interface is not the only thing writing to the
terminal.** Drawing writes only the cells that changed, so anything else
writing to the same device leaves damage no later frame repairs. On a server
that "anything else" is the kernel: console messages go straight to the device,
around the escape-sequence processing the alternate screen relies on, so the
alternate screen does not isolate the interface from them. That makes the
console a VPS panel offers — the one an unconfigured server is administered
from, before SSH is reachable — the place this is seen. It repaints rather than
suppressing anything: silencing kernel messages is machine-global state, and it
would blind the operator during exactly the changes worth watching.

The form is the one exception, and it is deliberate rather than an oversight:
`Ctrl-L` there opens the list of values the host offers, beside the readline
keys that dialog already answers to. A form also covers the screen it is drawn
over, which makes it the state least in need of a repaint.

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
| `→` | Open the selected category. Does nothing on a task |
| `/` | Open search over the whole tree |
| `h` | Open the recorded changes, with any one restorable |
| `Esc` / `Backspace` / `←` | Go back to the parent level; at the top level it reports rather than quitting |

Every row is selectable: a category that could not be selected could not be
opened. `Esc` means "go back" rather than "quit", so pressing it one level too
many cannot drop the user out of the program — `q` is the only way out.

**`→` is the inverse of `←` and deliberately narrower than `Enter`.** Without it
the arrows could walk out of a level but not into one, so descending needed
`Enter` while ascending had three keys of its own. What it does *not* do is run
a task: `Enter` on a task starts it, and an arrow is a movement key — an
operator descending a level and overshooting onto a task must not find that the
next `→` began changing the machine. On a task row it does nothing at all, which
is why the key bar does not advertise it there. The bar does not advertise it on
a category either: it would say what `Enter open` already says, and the bar sheds
hints by width, so a synonym would push out something that is not one. The help
overlay lists it, which is where every binding is enumerated.

A scrollbar appears on the right edge of the tree only when the level overflows
the pane; a track drawn against a level that fits is a permanent hint that
content is hidden when none is.

### Search (semi-modal)

Opened with `/` from the tree. Fifty tasks across six areas is past the
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
- **A line holding a secret is replaced in the copy, not omitted from it.** The
  pane still draws it — `wireguard.add-peer` prints a client configuration the
  operator has to read — but the clipboard receives a stand-in saying the value
  was left on screen. The copy is an extra journey nobody asked for: it crosses
  back over the SSH connection into a clipboard history that keeps it, which is
  the disclosure the task already refuses on disk by writing `wg0.conf` without
  a backup. Replacing rather than omitting, because a copy silently missing
  what was on screen reads as a complete record and gets pasted into a bug
  report as one. The CLI prints the same configuration to stdout unredacted,
  which is not the same decision reversed: there the output *is* the delivery,
  and the caller chooses where it lands.

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
| `Ctrl-L` | Open the full list of what the host offers, where it offers any — this dialog keeps the chord that repaints elsewhere |
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

**The asking is visible**, in the footer, where `Esc cancel` becomes
`Esc again to discard`. It was not for as long as the armed state was computed
and never drawn: the first press changed nothing on screen, which is exactly what
a dropped keypress looks like, and the reflex that invites is pressing `Esc`
again — the press that throws the values away. A guard nobody can see converts a
one-press loss into a two-press loss rather than preventing one. The ports table
draws the same hint for the same reason.

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

### Ports table (modal)

`firewall.manage-ports` collects a *set* rather than a fixed run of values, so
it opens a table instead of a form: one row per port the host admits, with rows
added and removed. Everything else about it follows the modal contract above.

The table is ruled — `PORT`, `PROTOCOL` and `SOURCE` divided by vertical lines,
with a horizontal rule above the heading, below it, and under the last row.
Three columns of left-aligned text read as one ragged block, and the eye has
nothing to follow down a value that is two characters in one row and five in
the next. The dialog is measured from its rows, so the rule closes directly
under the last port rather than at the foot of a frame taller than its content.

**The same rule cannot be listed twice.** A second row naming a port *and
protocol* another row already names is refused where the operator can still see
which keystroke caused it, and the message names the spec. The pair rather than
the number: `443/tcp` and `443/udp` are two different rules and both are
legitimate — SSH is TCP and WireGuard UDP on adjacent numbers often enough that
refusing the second would refuse a set an operator legitimately wants. The
typed value stays and the cell stays open, so there is something to correct.
Pressing `a` with an unfinished row already on screen moves to that row instead
of stacking another.

Two layers of keys, because a cell being edited has to swallow letters — `d`
removes a row while navigating and types a letter while editing.

**Navigating:**

| Key | Action |
|-----|--------|
| `↑` / `↓` (or `k` / `j`) | Move between rows |
| `a` | Append a row and open it for editing |
| `d` | Remove the focused row |
| `Enter` | Edit the focused row |
| `Tab` | Apply the set |
| `Esc` | Cancel — twice where the table has been edited |

**Editing a cell:**

| Key | Action |
|-----|--------|
| *printable*, `Backspace`, `Delete`, `←` / `→`, `Home`, `End`, `Ctrl-A/E/U/K/W` | Edit, exactly as a form field does |
| `↑` / `↓` | Step through `tcp` / `udp`, on the protocol cell |
| `Tab` | Commit the cell and move to the next |
| `Enter` | Commit the cell and close the editor |
| `Esc` | Discard the cell, leaving the row as it was |

`Tab` applies and `Enter` edits, which is the one binding here that disagrees
with the form. `Enter` opens what is under the cursor everywhere else in this
interface — a category, a task, a field — and taking that away to mean "apply"
would be the surprising half of the trade. `Tab` edits text nowhere, so it is
free to mean the thing that leaves.

**A row the host admits by a route this tool cannot undo is drawn and refused,
not hidden.** firewalld admits SSH on a stock RHEL host as the *service* `ssh`,
where `--remove-port 22/tcp` succeeds and closes nothing. Such rows are dim,
carry the service's name in the `SOURCE` column — the word as well as the
colour, since no signal here is carried by colour alone — and `d` on one
answers with a sentence naming what admits it. Hiding them was the alternative
and is worse in both directions: the operator would leave believing a port
closed, and the table would disagree with `firewall.status` on the same host
about what is open.

The terminal cursor appears only while a cell is open. Navigating, the focus bar
in the gutter says where the operator is — this is the one dialog that draws no
cursor most of the time.

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
configuration file is how a machine ends up in a state nobody chose. The request
lands between commands, so a task already on its last one finishes: what is
reported is what actually happened. Once the task has stopped, the output pane
reports where it got to under a `STOPPED` heading naming the command it stopped
*before*; a task that finished first is reported as done, with the near miss
said out loud rather than silently dropped.

**That a task is alive is said by the header**, which names it beside a turning
throbber and the time it has run. A spinner and a wall-clock timer used to ride
the status border for exactly that, and went with it when the status line was
removed; the write cursor was what remained, and it neither moves nor counts. The
signal is back in the header rather than in a band of its own, so it costs no
rows — and it names *which* task, which the status line never did. See *What the
interface says it is doing*.

**Asking to stop is acknowledged too.** The key bar drops `Ctrl-C stop` for
`stopping after this command` the moment the request lands, so the minute a
`dnf install` may take before anything else changes is not a minute of screen
that looks like a dropped keypress.

### Verification window (semi-modal)

Open after a change that could end the administrator's own session. Reading is
never blocked — the log is what the decision rests on — but nothing new may be
started until this change is settled.

| Key | Action |
|-----|--------|
| `K` | Keep the change |
| `R` | Put the previous configuration back now |
| `↑` / `↓` / `PageUp` / `PageDown` | Scroll the output |
| `?` | Open the help overlay, drawn over the window |
| *timer* | Puts the change back on its own after 60 seconds |
| *anything else* | Refused, restating what the two answers are |

**The banner outranks the pane the operator chose.** Below 72 columns one pane is
drawn at a time and `Tab` chooses which — and the tool never moves focus, so with
the cursor where it starts, a narrow terminal drew an ordinary task list while a
configuration file was already written and sixty seconds from being put back.
Nothing on screen said so: no countdown, no `K`/`R`, and the key bar is dropped
below 24 rows as well. At that width the window now takes the body whether or not
the output pane holds the focus. 60×15 is inside the supported range — a phone
SSH client, a split tmux pane — and a safety state that `Tab` can hide is one the
operator has to already know about in order to find.

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

**That line was written, documented here, and drawn at no terminal size for as
long as the banner had a fixed height.** The layout gave the banner five rows for
its top border and *five* lines, so the last one fell outside the area — measured
at 60×15, 72×24, 80×24, 100×30 and 120×40, absent from every one. The banner
therefore promised the revert unconditionally, which is the exact failure the
line exists to prevent, in the one place this document argues hardest that a
silent exception is corrosive. The height is now derived from the lines
themselves rather than chosen beside them, because the defect was not the number
five: it was that two things which must agree were free to be edited apart. A
test asserts the sentence reaches the buffer at each of those sizes, since
`Wrap` is on and a longer translation would push it out again.

### Confirmation dialog (modal)

| Key | Action |
|-----|--------|
| `Tab` / `←` / `→` | Switch between Yes and No |
| `↑` / `↓` / `k` / `j` | Scroll the warning, where it has more than it shows |
| `?` | Open the help overlay, drawn over the dialog |
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

`j` and `k` scroll it although the tree no longer takes them. They were added
here when it did, and are kept because this dialog can hold more than it shows,
neither letter means anything else in this state, and a hand already on them
loses nothing. `n` is deliberately not among them: it is the safe answer, and a
key that sometimes scrolls and sometimes cancels is one nobody presses with
confidence.

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
