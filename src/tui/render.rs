//! Drawing the interface, separate from deciding what it holds.
//!
//! `app.rs` owns the state and the keys that change it; this owns how that
//! state reaches the screen. The split is by responsibility rather than by
//! size: nothing here mutates the application except where a widget insists on
//! it, so a change to what is drawn cannot silently change what is stored.
//!
//! Shaped like the other drawing modules — [`super::search`], [`super::help`],
//! [`super::confirm`] — which are free functions over the state they render
//! rather than methods on it. [`all`] is the entry point; everything else is
//! reached from it.
//!
//! Two functions here take `&mut App`, for unrelated reasons, both of which
//! read as accidents and are not:
//!
//! - [`tree`], because `render_stateful_widget` *writes* the scroll offset
//!   back into the `ListState` it is handed, so the cursor has to be lent
//!   mutably in order to be drawn.
//! - [`all`], because a form draws its own scroll position and `Form::render`
//!   takes `&mut self` to do it.
//!
//! Everything else only reads.

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
    Wrap,
};

use super::app::{App, Mode, Pane, VERIFY_BANNER_ROWS, VERSION};
use super::probe::InstalledState;
use super::status::State;
use super::verify::Verification;
use super::{help, layout, search, style};
use crate::i18n::{Lang, Msg};
use crate::tasks::{Confirmation, Node, Task};

/// Marks a row that opens onto another level.
const CATEGORY_MARKER: &str = "› ";

/// Marks a runnable row, keeping task titles aligned with category ones.
const TASK_MARKER: &str = "  ";

/// Draws the whole interface.
///
/// A terminal too small for a legible interface gets a stated requirement
/// rather than a partial one: a garbled layout on a production server is
/// worse than a clear refusal.
pub(super) fn all(frame: &mut Frame, app: &mut App) {
    if !layout::is_usable(frame.area()) {
        too_small(frame, app.lang);
        return;
    }

    let bands = layout::frame(frame.area());

    header(frame, app, bands.header);
    body(frame, app, bands.body);

    if let Some(keys) = bands.keys {
        key_bar(frame, app, keys);
    }

    // Dialogs draw last, over everything: they are modal, and content
    // showing through one would misrepresent what the keys now do.
    //
    // One dialog, chosen by the same precedence the keys follow. These
    // used to be independent `if`s, which would have drawn a confirmation
    // and a form on top of each other had both ever existed — and the key
    // that answered would have gone to only one of them.
    //
    // `mode_under_help` rather than `mode`, because help is the one state
    // that draws *over* another rather than instead of it: what it was
    // opened on top of still has to be underneath.
    match app.mode_under_help() {
        Mode::Confirming(confirm) => confirm.render(frame, app.lang),
        Mode::Searching(search) => search::render(frame, search, app.lang),
        // Asked again below rather than borrowed here: `Form::render`
        // needs `&mut self` for its scroll state, which `mode` cannot
        // lend while it is borrowing the rest of `App`.
        Mode::Filling => {
            // Copied out first: the form is borrowed mutably for its
            // scroll state, which leaves the rest of `App` unreadable.
            let lang = app.lang;
            let options_at = app.options_at;

            if let Some(ref mut form) = app.form {
                form.render(frame, lang);

                // Over the form rather than instead of it: the field being
                // filled is the context for the choice, and a list that
                // replaced the form would hide which field it answers.
                if let Some(chosen) = options_at {
                    form.render_options(frame, chosen, lang);
                }
            }
        }
        // None of these draws a dialog: the countdown is a banner inside
        // the body, and a running task is the pane itself.
        Mode::Help | Mode::Running | Mode::Verifying | Mode::Browsing => {}
    }

    // Last of all, over whatever the operator was looking at when they
    // asked for it.
    if let Some(scroll) = app.help {
        help::render(frame, app.lang, scroll);
    }
}

/// Draws the one-line header naming the tool and the machine.
///
/// Borderless: at 24 rows a bordered header would spend three of them on
/// one line of text.
///
/// The hostname is emphasised because it answers the question an
/// administrator with several terminals open actually has — *which machine
/// am I about to change?* — and the privilege mechanism is stated up front
/// so that "this will need a password" is known before a task is started
/// rather than when one fails.
fn header(frame: &mut Frame, app: &App, area: Rect) {
    let separator = || Span::styled("  ·  ", style::BLOCK_SUBTITLE);

    // With one pane on screen at a time, nothing else says which one is
    // showing, so the header trades the host facts for an indicator —
    // otherwise `Tab` would look like it did nothing.
    let mut spans = if layout::BodyLayout::for_width(area.width) == layout::BodyLayout::Single {
        let (tree, output) = match app.focus {
            Pane::Tree => (style::EMPHASIS, style::BLOCK_SUBTITLE),
            Pane::Output => (style::BLOCK_SUBTITLE, style::EMPHASIS),
        };

        vec![
            Span::styled(app.lang.render(&Msg::HeaderTitle), style::HEADING),
            separator(),
            Span::styled(app.host.hostname.as_str(), style::EMPHASIS),
            Span::raw("  "),
            Span::styled(app.lang.render(&Msg::HeaderPaneTree), tree),
            Span::styled(" / ", style::BLOCK_SUBTITLE),
            Span::styled(app.lang.render(&Msg::HeaderPaneOutput), output),
        ]
    } else {
        vec![
            Span::styled(app.lang.render(&Msg::HeaderTitle), style::HEADING),
            Span::styled(format!(" {VERSION}"), style::BLOCK_SUBTITLE),
            separator(),
            Span::styled(app.host.hostname.as_str(), style::EMPHASIS),
            separator(),
            Span::styled(app.distro.display_name().to_owned(), style::NORMAL),
            separator(),
            Span::styled(
                app.lang.render(&Msg::HeaderPrivilege {
                    mechanism: app.host.privilege.to_string(),
                }),
                style::NORMAL,
            ),
        ]
    };

    // The help hint is dropped rather than allowed to wrap onto a row the
    // header does not have. Measured from the rendered text rather than
    // from a constant: a translation is a different width, and a hint
    // budgeted by English would wrap in any language whose word is longer.
    let hint = app.lang.render(&Msg::HeaderHelpHint);
    let used: usize = spans.iter().map(|span| cells(&span.content)).sum();
    let hint_width = cells(&hint) + 1;

    if used + hint_width <= area.width as usize {
        let gap = area.width as usize - used - hint_width;
        spans.push(Span::raw(" ".repeat(gap)));
        spans.push(Span::styled(hint, style::BLOCK_SUBTITLE));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Draws the task tree beside the output pane.
fn body(frame: &mut Frame, app: &mut App, area: Rect) {
    let split = layout::BodyLayout::for_width(area.width);
    let (tree_area, right_area) = layout::body(area, split);

    // Below the split threshold both panes are the whole area, so drawing
    // both would leave one written over the other. One is shown at a time
    // and `Tab` chooses which.
    if split == layout::BodyLayout::Single {
        match app.focus {
            // The status rides the right pane's border, and here that pane
            // may not be drawn at all — so the tree takes it while it is the
            // only thing on screen. Without this, `Tab` to the tree on a
            // narrow terminal hides the report of a task that just failed,
            // which is the one thing this line exists to prevent it doing.
            Pane::Tree => {
                // Built before the call rather than inside it: `tree` borrows
                // `App` mutably for the list's scroll state, which leaves
                // nothing to read the status from.
                let status = status_line(app, Instant::now(), tree_area.width);

                tree(frame, app, tree_area, status);
            }
            Pane::Output => right(frame, app, right_area),
        }

        return;
    }

    tree(frame, app, tree_area, None);
    right(frame, app, right_area);
}

/// Draws the task tree and its scrollbar.
///
/// `status` is `Some` only where the tree is the whole body — on a terminal
/// too narrow to show both panes, with focus here. Everywhere else the right
/// pane owns the status, and passing it to both would draw it twice.
fn tree(frame: &mut Frame, app: &mut App, tree_area: Rect, status: Option<Line<'static>>) {
    let family = app.distro.family;
    // The two borders and the marker column are not available to the row.
    let row_width = tree_area.width.saturating_sub(2) as usize;
    // Borrowed out before the level is walked: `current_level` borrows the
    // cursor, and a reversible row needs what the probe measured to know which
    // of its two verbs to draw.
    let presence = &app.presence;
    let items: Vec<ListItem> = app
        .cursor
        .current_level()
        .iter()
        .map(|node| ListItem::new(row(node, family, row_width, presence)))
        .collect();

    let tree_focused = app.focus == Pane::Tree;

    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_style(style::border(tree_focused))
        .title(Span::styled(
            // Two borders and the spaces framing the title.
            truncate_head(&app.breadcrumb(), tree_area.width.saturating_sub(4)),
            style::PANE_TITLE,
        ));

    match status {
        // Opposite the census, for the same reason the output pane puts it
        // opposite the follow indicator: ratatui aligns every bottom title
        // left, so two left-aligned titles are drawn over each other.
        //
        // Opposite ends is not enough on its own — ratatui does not arbitrate
        // between two titles that outgrow the border between them, it simply
        // draws both, and the census was rendered as `6 ca FAILED …`. So the
        // census yields entirely when the two will not fit: it counts rows
        // already on screen, while the status may be the only report of a task
        // that failed, and a half-eaten word beside it is worse than neither.
        Some(line) => {
            let status_width = line.width();

            if census_fits_beside(app, tree_area.width, status_width) {
                block = block.title_bottom(Span::styled(census(app), style::BLOCK_SUBTITLE));
            }

            block = block.title_bottom(line.right_aligned());
        }
        // The census rides the bottom border, costing no rows.
        None => block = block.title_bottom(Span::styled(census(app), style::BLOCK_SUBTITLE)),
    }

    let list = List::new(items)
        .block(block)
        // The selected row stays visible while focus is elsewhere, drawn
        // differently: losing the cursor on Tab would mean hunting for it
        // again on the way back.
        //
        // A row whose task cannot run here is drawn differently again. The
        // blue of the ordinary cursor reads as "press Enter", and pressing
        // it on an unsupported task does nothing — which looks like the
        // interface ignoring the key rather than the host refusing the
        // task. The pill and the detail pane both say so once the row is
        // selected; this makes the row itself say it too, before the eye
        // has moved. Colour is not carrying it alone: `MARKER_UNSUPPORTED`
        // is already in the flag column of the same row.
        .highlight_style(match (tree_focused, app.selected_is_runnable()) {
            (true, true) => style::SELECTION_FOCUSED,
            (true, false) => style::SELECTION_DISABLED,
            (false, _) => style::SELECTION_UNFOCUSED,
        });

    // These two are ordered, not merely sequential. Drawing the list is what
    // *writes* the scroll offset — `render_stateful_widget` mutates the
    // `ListState` it is lent, moving the window when the cursor has left it —
    // and the scrollbar below reads that same offset to place its thumb.
    // Swapping them draws the thumb from the previous frame's offset, so the
    // track lags the selection by one keypress. Nothing catches it: both
    // orders compile, both draw a scrollbar, and a test that presses a key
    // once and looks at the result sees a plausible position either way.
    frame.render_stateful_widget(list, tree_area, app.cursor.list_state());
    tree_scrollbar(frame, app, tree_area);
}

/// Draws whichever of detail, output or verification the state calls for.
///
/// Whichever it is takes the status on its bottom border. The status used to
/// have a row to itself, below all three, so it was drawn once and none of
/// them had to know about it; on a border it belongs to whichever pane owns
/// the bottom of the area, which is why it is built here and handed down
/// rather than drawn by each.
fn right(frame: &mut Frame, app: &App, right_area: Rect) {
    let status = status_line(app, Instant::now(), right_area.width);

    if let Some(ref window) = app.verification {
        // The countdown takes the top of the pane and the output keeps the
        // rest: what the change did is the evidence for the decision.
        let [banner, log] =
            Layout::vertical([Constraint::Length(VERIFY_BANNER_ROWS), Constraint::Min(3)])
                .areas(right_area);

        verification(frame, banner, window, app.lang);
        app.output
            .render(frame, log, app.lang, app.focus == Pane::Output, status);
    } else if app.output.is_empty() {
        detail(frame, app, right_area, status);
    } else {
        app.output.render(
            frame,
            right_area,
            app.lang,
            app.focus == Pane::Output,
            status,
        );
    }
}

/// Draws the tree's scrollbar, but only when there is something to scroll.
///
/// A track drawn against a level that fits is a permanent hint that
/// content is hidden when none is.
fn tree_scrollbar(frame: &mut Frame, app: &App, area: Rect) {
    let rows = app.current_level().len();
    // The block's own borders are not available to the list.
    let viewport = area.height.saturating_sub(2) as usize;

    if rows <= viewport {
        return;
    }

    let mut state =
        ScrollbarState::new(rows.saturating_sub(viewport)).position(app.cursor.offset());

    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .style(style::SCROLLBAR_TRACK)
            .thumb_style(style::SCROLLBAR_THUMB),
        area,
        &mut state,
    );
}

/// Draws what the selected row would do, before anything has run.
///
/// A category has no description of its own, so it reports what it holds
/// rather than leaving the pane blank.
fn detail(frame: &mut Frame, app: &App, area: Rect, status: Option<Line<'static>>) {
    // A reversible pair is reduced to the task the row is drawing, so the
    // description reads about the operation the operator would actually start.
    // Resolved through the same function the row draws through, so the pane
    // can never describe one half while the row offers the other.
    let selected = app.selected_task();

    // A task that cannot run here says why, under what it would have done. The
    // tree already dims the row and the pill already reads UNSUPPORTED — both
    // of which state *that* it is refused and neither of which states why,
    // leaving the operator to guess whether it is a missing package, a policy,
    // or a bug. The reasons were measured; this is where they were always meant
    // to be read.
    let description = if let Some(task) = selected {
        match task.unsupported_reason(app.distro.family) {
            // The blank line between the two is written here rather than
            // in the catalogue: the description above it is the task's own
            // words, and running the two together would read as one
            // sentence written by whoever wrote the task.
            Some(reason) => format!(
                "{}\n\n{}",
                task.description(),
                app.lang.render(&Msg::DetailUnsupported {
                    family: app.distro.family.to_string(),
                    reason: reason.to_owned(),
                })
            ),
            None => task.description().to_owned(),
        }
    } else if let Some(Node::Category(category)) = app.selected_node() {
        app.lang.render(&Msg::DetailCategoryContents {
            title: category.title.to_owned(),
            count: category.task_count(),
        })
    } else {
        String::new()
    };

    let title = match selected {
        Some(task) => task.title().to_owned(),
        None => app.lang.render(&Msg::DetailTitle),
    };

    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_style(style::border(app.focus == Pane::Output))
        .title(Span::styled(
            truncate_head(&title, area.width.saturating_sub(4)),
            style::PANE_TITLE,
        ));

    // Right-aligned even though this border is otherwise empty, so the status
    // sits in the same corner whether the pane holds a description or a log.
    // Left would put it under the tree's census on one and beside nothing on
    // the other, moving between two panes that swap without warning.
    if let Some(line) = status {
        block = block.title_bottom(line.right_aligned());
    }

    let paragraph = Paragraph::new(description)
        .block(block)
        .wrap(Wrap { trim: true });

    frame.render_widget(paragraph, area);
}

/// Whether the census and a status of `status_width` both fit on one border.
///
/// They share the bottom border of the tree only on a terminal too narrow to
/// show both panes, which is exactly where the room runs out. Ratatui draws
/// both regardless and lets them overlap, so the caller asks first.
///
/// The gap is not decoration: two titles that merely touch read as one string,
/// and `6 categoriesFAILED` is a worse answer than dropping the census.
fn census_fits_beside(app: &App, border_width: u16, status_width: usize) -> bool {
    /// Cells that must stay blank between the two.
    const GAP: usize = 2;

    // The border's own two corners are not available to either title.
    let available = (border_width as usize).saturating_sub(2);

    cells(&census(app)) + GAP + status_width <= available
}

/// Counts what the level on screen holds, for the tree's bottom border.
fn census(app: &App) -> String {
    let level = app.current_level();
    let categories = level
        .iter()
        .filter(|node| matches!(node, Node::Category(_)))
        .count();
    let tasks = level.len() - categories;

    // Each part is rendered whole rather than assembled from a count and a
    // noun here: agreeing the plural is the language's job, and the
    // catalogue is where a language that inflects differently can do it.
    let parts: Vec<String> = [
        Msg::CensusCategories { count: categories },
        Msg::CensusTasks { count: tasks },
    ]
    .iter()
    .zip([categories, tasks])
    .filter(|(_, count)| *count > 0)
    .map(|(message, _)| app.lang.render(message))
    .collect();

    format!(" {} ", parts.join(", "))
}

/// What the tool is doing, for the right pane's bottom border.
///
/// The status used to own a row of its own, with the state on a coloured
/// background at the left edge. It rides a border now, which costs the
/// background — filled cells there read as a gap in the frame rather than as
/// emphasis — and returns the row to the body. What the background carried is
/// carried by the word and its colour instead.
///
/// Returns `None` when there is nothing to say, so that a border with no
/// status draws unbroken rather than with an empty notch in it.
///
/// The order is the order it is read in: liveness first, because a spinner
/// that has stopped is the fastest thing on screen to check; then the state;
/// then what it is doing. The spinner leads rather than trails so it sits at a
/// fixed distance from the corner while the message beside it changes length.
///
/// The message is what gives way when the line outgrows the border, and that
/// is the whole reason `width` is a parameter. A `title_bottom` wider than its
/// block is cut by ratatui at the end the alignment anchors away from — for a
/// right-aligned line, the head — which took the first characters of `VERIFY`
/// and left `RIFY` on screen during the one state whose word the operator must
/// not misread. Truncating here means the label and the liveness signals are
/// never the part that goes.
fn status_line(app: &App, now: Instant, width: u16) -> Option<Line<'static>> {
    let state = pill(app);
    let mut spans = Vec::new();

    // Two independent liveness signals: a spinner driven by the clock and a
    // wall-clock timer. Both keep moving through a command that produces no
    // output for a minute, which is what distinguishes a slow package manager
    // from a frozen screen over a bad link.
    if let Some(ref running) = app.running {
        spans.push(Span::styled(
            format!("{}  {}", running.spinner(now), running.elapsed(now)),
            style::BLOCK_SUBTITLE,
        ));
    }

    if state.is_worth_naming() {
        if !spans.is_empty() {
            spans.push(Span::styled("  ·  ", style::BLOCK_SUBTITLE));
        }

        spans.push(Span::styled(app.lang.render(&state.label()), state.style()));
    }

    let message = app.status.message(now);

    if !message.is_empty() {
        // Below this, what survives truncation is not a shortened sentence but
        // a smear, and the message is dropped whole instead. The state's word
        // is still on the border, and it is the part carrying the meaning.
        const LEGIBLE_MINIMUM: usize = 8;

        // Two borders, the two spaces framing the line, and the separator this
        // message would add are all spoken for before it gets a cell.
        let spent: usize = spans.iter().map(|span| cells(&span.content)).sum();
        let reserved = spent + if spans.is_empty() { 4 } else { 9 };
        let available = (width as usize).saturating_sub(reserved);

        if available >= LEGIBLE_MINIMUM {
            if !spans.is_empty() {
                spans.push(Span::styled("  ·  ", style::BLOCK_SUBTITLE));
            }

            spans.push(Span::styled(
                truncate_tail(message, available),
                style::NORMAL,
            ));
        }
    }

    if spans.is_empty() {
        return None;
    }

    // The spaces are what hold the border off the text; without them the line
    // reads as though the frame had been drawn through it.
    spans.insert(0, Span::raw(" "));
    spans.push(Span::raw(" "));

    Some(Line::from(spans))
}

/// The state naming what the tool is doing.
///
/// Mostly this is whatever the last action left behind, but two conditions
/// describe the cursor rather than the past and therefore win: a dialog is
/// open, or the row under the cursor cannot run here. It is the one place
/// that always states what pressing Enter would do.
///
/// The confirmation outranks the form for the same reason the row flag
/// does: a destructive task collects its parameters first and confirms
/// after, so once both are open the confirmation is the live question.
pub(super) fn pill(app: &App) -> State {
    match app.mode() {
        // These three carry their own pill through `status`, set when the
        // state was entered: `Busy` while a task runs, `Verify` while a
        // change is unsettled. Asking here would duplicate that.
        Mode::Help | Mode::Running | Mode::Verifying => app.status.state(),
        Mode::Confirming(_) => State::Confirm,
        Mode::Filling => State::Input,
        // Search names no pill of its own: it changes what the keys do,
        // not what the interface is in the middle of.
        Mode::Searching(_) | Mode::Browsing => match app.selected_node() {
            Some(Node::Task(task)) if !task.supports(app.distro.family) => State::Unsupported,
            _ => app.status.state(),
        },
    }
}

/// The hints offered while the tree holds focus.
///
/// `Enter` opens a category but runs a task, so the hint names which of
/// the two it is rather than listing both every time.
fn tree_keys(app: &App) -> Vec<(&'static str, Msg)> {
    let enter_hint = match app.selected_node() {
        Some(Node::Category(_)) => Msg::KeyBarOpen,
        _ => Msg::KeyBarRun,
    };

    // Search is offered from the tree and nowhere else: it exists to reach
    // a task, and the pane holds no tasks to reach.
    let mut keys = vec![
        ("↑↓", Msg::KeyBarMove),
        ("Enter", enter_hint),
        ("/", Msg::KeyBarFind),
    ];

    // Going back is only offered where there is somewhere to go back to.
    if !app.cursor.at_root() {
        keys.push(("Esc", Msg::KeyBarBack));
    }

    // Switching panes is pointless with nothing to read.
    if !app.output.is_empty() {
        keys.push(("Tab", Msg::KeyBarOutput));
    }

    keys
}

/// Draws the key hints along the bottom row.
///
/// The hints follow the focused pane and the row under the cursor rather
/// than listing every binding: a bar that never changes is one the operator
/// stops reading.
fn key_bar(frame: &mut Frame, app: &App, area: Rect) {
    // While a change is unverified the tree keys are refused, so offering
    // them would advertise actions the state does not allow.
    // Only the keys the state actually accepts. Offering "Enter run" while
    // a task is running would name an action that is refused — so this
    // asks the same `mode` the dispatcher does, rather than re-deriving
    // which state wins and drifting from it.
    let mut keys = match app.mode() {
        Mode::Running => vec![
            ("Ctrl-C", Msg::KeyBarStop),
            ("↑↓", Msg::KeyBarScroll),
            ("?", Msg::KeyBarKeys),
        ],
        Mode::Verifying => vec![
            ("K", Msg::KeyBarKeep),
            ("R", Msg::KeyBarRevert),
            ("↑↓", Msg::KeyBarScroll),
        ],
        Mode::Searching(_) => vec![
            ("↑↓", Msg::KeyBarMove),
            ("Enter", Msg::KeyBarGo),
            ("Esc", Msg::KeyBarClose),
        ],
        // Both draw their own keys inside the dialog, where the operator
        // is already looking; repeating them along the bottom would be
        // the same hint twice.
        Mode::Filling | Mode::Confirming(_) => Vec::new(),
        // The overlay states its own keys, and it covers this row anyway.
        Mode::Help => Vec::new(),
        Mode::Browsing => match app.focus {
            Pane::Tree => tree_keys(app),
            Pane::Output => vec![
                ("↑↓", Msg::KeyBarScroll),
                ("G", Msg::KeyBarFollow),
                ("y", Msg::KeyBarCopy),
                ("Tab", Msg::KeyBarTree),
            ],
        },
    };

    // Quitting is refused while work is outstanding: mid-task it would
    // leave a server half-configured, and mid-verification it would
    // abandon a change with nobody left to put it back.
    if !matches!(app.mode(), Mode::Running | Mode::Verifying) {
        keys.push(("q", Msg::KeyBarQuit));
    }

    let mut spans = Vec::with_capacity(keys.len() * 3);
    for (key, label) in keys {
        // The spaces around each pair are the bar's own separation rather
        // than part of either word, so they stay here: a label that
        // carried them could not be reused where the spacing differs.
        spans.push(Span::styled(format!(" {key}"), style::KEYBAR_KEY));
        spans.push(Span::styled(
            format!(" {} ", app.lang.render(&label)),
            style::KEYBAR_LABEL,
        ));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Draws the banner over an applied change that has not been kept.
///
/// It states three things in order: that the change is applied but not yet
/// permanent, how long is left, and what to press. The countdown is red
/// because it is the one number on screen that acts on its own.
fn verification(frame: &mut Frame, area: Rect, window: &Verification, lang: Lang) {
    let lines = vec![
        Line::from(vec![
            Span::styled(lang.render(&Msg::VerifyBadge), style::BADGE_BUSY),
            Span::raw("  "),
            Span::styled(lang.render(&Msg::VerifyApplied), style::NORMAL),
            Span::styled(lang.render(&Msg::VerifyNotYetKept), style::EMPHASIS),
        ]),
        Line::from(vec![
            Span::styled(lang.render(&Msg::VerifyRevertingIn), style::DANGER_TEXT),
            Span::styled(window.countdown(Instant::now()), style::EMPHASIS),
            Span::raw("   "),
            Span::styled("K", style::KEYBAR_KEY),
            Span::styled(lang.render(&Msg::VerifyKeepKey), style::KEYBAR_LABEL),
            Span::styled("R", style::KEYBAR_KEY),
            Span::styled(lang.render(&Msg::VerifyRevertKey), style::KEYBAR_LABEL),
        ]),
        // The instruction that matters: the tool cannot check this itself, so
        // the one thing the administrator must do is stated outright.
        Line::styled(
            lang.render(&Msg::VerifyCheckSecondSessionLine1),
            style::EMPHASIS,
        ),
        Line::styled(
            lang.render(&Msg::VerifyCheckSecondSessionLine2),
            style::EMPHASIS,
        ),
        // What the countdown depends on, said rather than implied. A dropped
        // connection and an ordinary kill both revert, because the signals are
        // caught; a `SIGKILL` or a machine losing power run no code at all, so
        // the change would stay. Stating the limit is what makes the sentence
        // above trustworthy — a promise with a silent exception teaches people
        // to disbelieve the whole banner.
        Line::styled(
            lang.render(&Msg::VerifySessionScopeCaveat),
            style::CONSEQUENCE_EXTERNAL,
        ),
    ];

    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::TOP | Borders::LEFT | Borders::RIGHT)
                    .border_style(style::DIALOG_BORDER_DANGER),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

/// Builds one row of the tree.
///
/// Flags are glyphs rather than colours so that a monochrome terminal loses
/// nothing, and unsupported tasks stay visible with their reason rather than
/// being hidden — hiding them makes the tool look inconsistent between hosts.
pub(super) fn row(
    node: &Node,
    family: crate::distro::Family,
    width: usize,
    presence: &InstalledState,
) -> Line<'static> {
    let RowParts {
        marker,
        marker_style,
        title,
        title_style,
        trailing,
        trailing_style,
    } = match node {
        // The marker tells a category apart from a task at a glance; with one
        // level on screen there is no indentation to do it.
        //
        // The count is what makes a collapsed level navigable: it tells a
        // 3-task category from an 8-task one without opening either.
        Node::Category(category) => RowParts {
            marker: CATEGORY_MARKER,
            marker_style: style::CATEGORY_COLLAPSED,
            title: category.title,
            title_style: style::HEADING,
            trailing: category.task_count().to_string(),
            trailing_style: style::BLOCK_SUBTITLE,
        },
        // Drawn as whichever half the host justifies, through the same
        // resolution the keys act through. Until the probe answers that is the
        // forward task: a row offering to install what is already there wastes
        // a keystroke, while one offering to remove what was never installed
        // does nothing and explains nothing.
        Node::Reversible { forward, inverse } => {
            let measured = presence.of(forward.id());
            let drawn = if measured.calls_for_the_inverse() {
                inverse
            } else {
                forward
            };

            let mut parts = task_row_parts(drawn.as_ref(), family);

            // Ahead of the task's own flag, and only while the answer is
            // outstanding. A row showing "Install" because nothing has been
            // measured is not the same as one showing it because the subject
            // was found absent, and the difference lasts a few hundred
            // milliseconds — long enough to press a key in.
            if !measured.is_settled() && parts.trailing.is_empty() {
                parts.trailing = style::MARKER_PROBING.to_owned();
                parts.trailing_style = style::BLOCK_SUBTITLE;
            }

            parts
        }
        Node::Task(task) => task_row_parts(task.as_ref(), family),
    };

    // A title longer than its column is cut with an ellipsis rather than
    // silently clipped by the terminal: "Install and enable the SSH ser" reads
    // as a real name, so the operator cannot tell it was truncated.
    //
    // Titles lose their tail, unlike breadcrumbs, which lose their head: a task
    // is identified by how its name starts, a path by where it ends.
    let fixed = cells(marker) + cells(&trailing);
    // One space always separates the title from the trailing flag.
    let room_for_title = width.saturating_sub(fixed + 1);
    let title = truncate_tail(title, room_for_title);

    let used = fixed + cells(&title);
    let padding = width.saturating_sub(used).max(1);

    Line::from(vec![
        Span::styled(marker, marker_style),
        Span::styled(title, title_style),
        Span::raw(" ".repeat(padding)),
        Span::styled(trailing, trailing_style),
    ])
}

/// What one row draws, before it is measured against the column width.
///
/// A struct rather than the tuple this began as: six positional fields where
/// four are styles is a shape where two can be swapped without the compiler
/// noticing, and the pair arm below needs to reach one of them by name.
struct RowParts {
    marker: &'static str,
    marker_style: Style,
    title: &'static str,
    title_style: Style,
    trailing: String,
    trailing_style: Style,
}

/// The marker, title and flag a single task contributes to its row.
///
/// Extracted so a reversible pair draws through exactly the same precedence as
/// a lone task: the flag column answers "what should stop me acting on this
/// row", and a second copy of that rule would be the one that drifted.
fn task_row_parts(task: &dyn Task, family: crate::distro::Family) -> RowParts {
    let supported = task.supports(family);
    // Destructive outranks input: a task that asks for a port before
    // wiping something is first of all the one that wipes something,
    // and only one flag fits the column.
    let (text_style, flag, flag_style) = if !supported {
        (
            style::DISABLED,
            style::MARKER_UNSUPPORTED,
            style::FLAG_UNSUPPORTED,
        )
    // `Lockout` alone, not every task that asks. Almost all of them
    // ask now, and a danger flag on almost every row marks nothing —
    // the column exists to say which handful can end the session
    // reading it.
    } else if task.confirmation() == Confirmation::Lockout {
        (style::NORMAL, style::MARKER_DANGER, style::FLAG_DANGER)
    } else if !task.params().is_empty() {
        (style::NORMAL, style::MARKER_INPUT, style::FLAG_INPUT)
    } else {
        (style::NORMAL, "", style::NORMAL)
    };

    RowParts {
        marker: TASK_MARKER,
        marker_style: text_style,
        title: task.title(),
        title_style: text_style,
        trailing: flag.to_owned(),
        trailing_style: flag_style,
    }
}

/// How many terminal cells a string occupies.
///
/// Not its character count, which is what every measurement here used to be. A
/// CJK ideograph and most emoji take two cells, so `admin@東京サーバー本番` is
/// fourteen characters and twenty-two cells: a pane twenty wide was told it
/// fitted, wrote no ellipsis, and let ratatui cut two cells off the end. What
/// is lost is the mark that says something was lost.
///
/// Reachable rather than hypothetical: `ParamKind::PublicKey` admits any
/// non-control character and `is_valid_public_key` checks the type and the
/// base64 body, never the comment — so `ssh-ed25519 AAAA… admin@東京` is a
/// valid key that reaches the screen.
///
/// Measured through ratatui rather than by depending on `unicode-width`
/// directly. The crate is already in the tree beneath ratatui, so this adds no
/// name to audit either way, but `Span::width` is the number ratatui itself
/// will use when it draws the same text — asking the drawing layer is what
/// keeps the two from disagreeing.
pub(super) fn cells(text: &str) -> usize {
    Span::raw(text).width()
}

/// Fits `text` into `width` cells, dropping characters from the end.
///
/// The companion of [`truncate_head`], for text identified by how it starts.
pub(super) fn truncate_tail(text: &str, width: usize) -> String {
    if cells(text) <= width {
        return text.to_owned();
    }

    // Too narrow to say anything meaningful; an ellipsis alone is honest.
    if width <= 1 {
        return "…".repeat(width);
    }

    // Accumulated by cell rather than taken by count: a wide character straddles
    // the boundary, so the last one that fits is found by adding them up.
    let mut kept = String::new();
    let mut used = 0;

    for character in text.chars() {
        let next = used + cells(character.encode_utf8(&mut [0; 4]));

        // One cell is reserved for the ellipsis.
        if next > width - 1 {
            break;
        }

        kept.push(character);
        used = next;
    }

    kept.push('…');
    kept
}

/// Fits `text` into `width` cells, dropping characters from the front.
///
/// Paths lose their head, never their tail: `…› Configuration` says where you
/// are, whereas `Remote Access › SSH › Configura` does not. The result is
/// padded with a space on each side, the way every title in the interface is
/// framed against its border.
pub(super) fn truncate_head(text: &str, width: u16) -> String {
    let available = width as usize;

    if cells(text) <= available {
        return format!(" {text} ");
    }

    // Kept from the back, one cell at a time, since a wide character cannot be
    // half included. One cell goes to the ellipsis marking the dropped head.
    let budget = available.saturating_sub(1);
    let mut kept = String::new();
    let mut used = 0;

    for character in text.chars().rev() {
        let next = used + cells(character.encode_utf8(&mut [0; 4]));

        if next > budget {
            break;
        }

        kept.insert(0, character);
        used = next;
    }

    format!(" …{kept} ")
}

/// Draws the refusal shown on a terminal too small for a legible interface.
fn too_small(frame: &mut Frame, lang: Lang) {
    let message = lang.render(&Msg::TerminalTooSmall {
        min_width: layout::MIN_WIDTH,
        min_height: layout::MIN_HEIGHT,
        width: frame.area().width,
        height: frame.area().height,
    });

    frame.render_widget(
        Paragraph::new(message)
            .style(style::NORMAL)
            .wrap(Wrap { trim: true }),
        frame.area(),
    );
}
