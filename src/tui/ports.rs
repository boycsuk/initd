//! The modal table of ports a firewall admits.
//!
//! Every other task collects its values through [`Form`](super::form::Form),
//! which draws one field per parameter and knows how many there are before it
//! opens. A set of ports is not that shape: the operator adds rows, removes
//! them, and leaves with a list whose length nothing declared in advance. So
//! this is the one dialog whose contents are a `Vec` rather than a fixed run of
//! fields.
//!
//! What crosses back out is still one parameter, spelled the way every
//! front-end spells a port — `22/tcp 443/tcp`. The table is a way of editing a
//! string, which is what keeps the CLI able to express the same thing without a
//! second grammar.
//!
//! Rows the host admits by a route this tool cannot undo are drawn and refused
//! rather than hidden. firewalld admits SSH on a stock RHEL host as the service
//! `ssh`, and `--remove-port 22/tcp` there succeeds while changing nothing: a
//! table that offered to delete that row would report closing a port that stays
//! open, and one that omitted the row would disagree with `firewall.status` on
//! the same host about what is open.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, List, ListItem, ListState, Paragraph};

use super::field::Field;
use super::{layout, style};
use crate::domain::firewall::{AllowedPort, PortOrigin};
use crate::i18n::{Lang, Msg};
use crate::tasks::params::{Param, ParamKind};

/// Width the dialog is drawn at, before clamping to the terminal.
///
/// Wider than [`layout::DIALOG_WIDTH`], and the one dialog here that is. The
/// shared 72 is a floor set by the parameter form's footer — the longest fixed
/// string a modal draws — and every other dialog's content is prose, which
/// reads worse the wider it gets. This one's content is a table: columns need
/// room to be columns rather than words that happen to line up, and the
/// `SOURCE` column carries a service name beside them.
const DIALOG_WIDTH: u16 = 88;

/// Rows spent on the dialog's own frame and the table's chrome.
///
/// The two borders — the footer rides the bottom one — the blank row the block
/// is inset by above the table, and the table's own three rules with the
/// heading between two of them.
///
/// Counted against a screen dump rather than reasoned about, three times. Eight
/// left two blank rows between the table and the footer; six was one too few
/// and dropped the last port off the bottom, which is the more expensive
/// direction — a row missing from a table of open ports is a port the operator
/// does not know is open. Space is the one thing no assertion in this suite was
/// watching for, which is why each of the three was found by looking.
const CHROME_ROWS: u16 = 7;

/// The rows a refusal needs, on the frames where one is standing.
///
/// Added to the height rather than taken from the rows, so a message appearing
/// does not push the last port out of the dialog it is being read in.
///
/// One, measured rather than reserved: the longest of them names a service and
/// says what removing the port does not do, which is 77 cells and fits this
/// dialog's 88 with room to spare. It was two while the dialog was 72 wide,
/// where the same sentence wrapped — a constant chosen for a width that then
/// changed, which is the failure this project has written down before.
const REFUSAL_ROWS: u16 = 1;

/// Most rows drawn before the list scrolls.
///
/// The ceiling exists for the same reason the options overlay has one: a host
/// admitting forty ports would otherwise claim the whole screen, and the tree
/// underneath is the context for what is being edited.
const MAX_VISIBLE_ROWS: u16 = 14;

/// The blank row separating the table from the footer.
///
/// One, and named for what it is rather than for what an earlier version hoped
/// it would buy: it was `ROOM_TO_ADD`, on the theory that a spare row meant
/// pressing `a` would not move the dialog. It does move — the dialog is
/// measured from its content, so a row added is a row taller — and a constant
/// promising otherwise was a comment disagreeing with its own code.
const FOOTER_GAP: u16 = 1;

/// Width the port column is drawn at, between its rules.
///
/// Wide enough for a five-digit port and the range firewalld may report
/// (`8000-8080`), with room either side so the value does not touch the rule.
const PORT_WIDTH: usize = 13;

/// Width the protocol column is drawn at, between its rules.
const PROTOCOL_WIDTH: usize = 12;

/// Marks the row the keystrokes reach, in the gutter left of the table.
///
/// The same bar the form uses, for the same reason and drawn the same way:
/// inside the dialog's area rather than over its border, and two cells wide so
/// it does not read as the first character of the value.
const FOCUS_BAR: &str = "▌ ";

/// Cells the gutter occupies, bar or no bar.
///
/// Counted rather than derived from `FOCUS_BAR.len()`, which is bytes: `▌` is
/// three of them and one cell.
const GUTTER_WIDTH: usize = 2;

/// The vertical rule between two columns.
///
/// A real rule rather than spacing: three columns of left-aligned text read as
/// one ragged block, and the eye has nothing to follow down a value that is
/// two characters in one row and five in the next.
const COLUMN_RULE: char = '│';

/// The protocols a rule may name.
///
/// Stated once and used twice — as what the parameter offers and as what the
/// cell steps through — because a field that offered one list and validated
/// against another would refuse a value it had just suggested.
const PROTOCOLS: &[&str] = &["tcp", "udp"];

/// Which half of a row is being edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Column {
    Port,
    Protocol,
}

/// One row of the table.
#[derive(Debug, Clone)]
struct PortRow {
    port: String,
    protocol: String,
    /// How the host came to admit this, or [`PortOrigin::Direct`] for a row the
    /// operator added.
    origin: PortOrigin,
    /// Whether this row was not there when the table opened.
    added: bool,
}

impl PortRow {
    /// The row as a `port/protocol` spec.
    fn spec(&self) -> String {
        format!("{}/{}", self.port, self.protocol)
    }

    /// Whether the task could actually close this if the row were removed.
    const fn is_closeable(&self) -> bool {
        matches!(self.origin, PortOrigin::Direct)
    }
}

/// A cell being edited.
#[derive(Debug)]
struct Editing {
    row: usize,
    column: Column,
    /// The editor itself, reused wholesale from the form's fields.
    ///
    /// Cursor movement, the readline bindings, live validation and the
    /// scrolling window over a value wider than its column all come from here
    /// rather than being written a second time for a cell.
    field: Field,
}

/// The table of admitted ports, while it is being edited.
#[derive(Debug)]
pub struct PortTable {
    /// What the table is collecting for, drawn on the frame.
    pub title: String,
    rows: Vec<PortRow>,
    /// Which row the keystrokes reach.
    focus: usize,
    /// The cell being edited, where one is.
    ///
    /// One `Option` rather than a flag beside a column, so "not editing" and
    /// "editing nothing in particular" cannot both be representable — the
    /// discipline `options_at` already applies to the overlay.
    editing: Option<Editing>,
    /// What the host admitted when this opened.
    ///
    /// Kept so the task can tell a port the operator removed from one that
    /// appeared while they were deciding. Without it the two are the same
    /// difference and the second would be silently closed.
    opened_on: Vec<String>,
    /// Why the last keystroke was refused, drawn above the footer.
    ///
    /// Cleared by the next keystroke, so an explanation cannot outlive the
    /// action it belongs to and answer for a later one.
    refusal: Option<Msg>,
    /// Whether a second `Esc` would discard the edits.
    cancel_armed: bool,
}

impl PortTable {
    /// Builds a table over what the host currently admits.
    pub fn new(title: impl Into<String>, admitted: &[AllowedPort]) -> Self {
        let rows: Vec<PortRow> = admitted
            .iter()
            .map(|port| {
                let (number, protocol) = port
                    .spec
                    .split_once('/')
                    .unwrap_or((port.spec.as_str(), ""));

                PortRow {
                    port: number.to_owned(),
                    protocol: protocol.to_owned(),
                    origin: port.origin.clone(),
                    added: false,
                }
            })
            .collect();

        Self {
            title: title.into(),
            opened_on: rows.iter().map(PortRow::spec).collect(),
            rows,
            focus: 0,
            editing: None,
            refusal: None,
            cancel_armed: false,
        }
    }

    /// The declared set, as the parameter spells it.
    pub fn value(&self) -> String {
        // Duplicates are left to the task, which drops them: two rows naming
        // one port admit it exactly as one row does, and refusing to submit
        // over that would block a set that means what it says.
        self.rows
            .iter()
            .map(PortRow::spec)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// What the host admitted when the table opened.
    pub fn opened_on(&self) -> String {
        self.opened_on.join(" ")
    }

    /// Whether anything has been changed since the table opened.
    ///
    /// Asked so `Esc` can close a table nobody edited without demanding a
    /// second press, the way the form does.
    pub fn is_untouched(&self) -> bool {
        self.editing.is_none() && self.value() == self.opened_on()
    }

    /// Arms cancellation, so a second `Esc` discards the edits.
    pub const fn arm_cancel(&mut self) {
        self.cancel_armed = true;
    }

    /// Whether `Esc` has already been pressed once with edits in the table.
    pub const fn cancel_armed(&self) -> bool {
        self.cancel_armed
    }

    /// Cancels the arming, for any key that is not `Esc`.
    pub const fn disarm_cancel(&mut self) {
        self.cancel_armed = false;
    }

    /// Whether a cell is currently being edited.
    pub const fn is_editing(&self) -> bool {
        self.editing.is_some()
    }

    /// The cell being edited, for the keys that act on one.
    pub fn editing_field(&mut self) -> Option<&mut Field> {
        self.editing.as_mut().map(|editing| &mut editing.field)
    }

    /// Clears whatever the last refusal said.
    pub fn forget_refusal(&mut self) {
        self.refusal = None;
    }

    /// Moves the focus one row down.
    pub const fn focus_next(&mut self) {
        if !self.rows.is_empty() && self.focus + 1 < self.rows.len() {
            self.focus += 1;
        }
    }

    /// Moves the focus one row up.
    pub const fn focus_previous(&mut self) {
        self.focus = self.focus.saturating_sub(1);
    }

    /// Appends an empty row and opens it for editing.
    ///
    /// `tcp` rather than empty, because it is the answer four times out of
    /// five and a field pre-filled with the common case is one `Tab` away from
    /// the other.
    pub fn add_row(&mut self) {
        // Cleared here rather than only in the dispatcher: an explanation that
        // outlives the keystroke it belongs to reads as an answer to the next
        // one, and the table is what knows a row was just added.
        self.refusal = None;

        // One unfinished row at a time. Holding `a` would otherwise leave a
        // column of empty rows, each of which has to be filled or removed
        // before the table can submit — and the refusal that stops it names
        // only the first.
        if let Some(unfinished) = self.first_invalid() {
            self.focus = unfinished;
            self.edit(Column::Port);

            return;
        }

        self.rows.push(PortRow {
            port: String::new(),
            protocol: "tcp".to_owned(),
            origin: PortOrigin::Direct,
            added: true,
        });

        self.focus = self.rows.len() - 1;
        self.edit(Column::Port);
    }

    /// Removes the focused row, where this tool could actually close it.
    ///
    /// Refuses the rows it cannot, naming what admits them. Accepting the
    /// keystroke and reporting the failure afterwards was the alternative, and
    /// it is worse in the one way that matters: the operator would leave the
    /// table believing a port closed, and find out from a line of output after
    /// the change was applied.
    pub fn remove_row(&mut self) {
        let Some(row) = self.rows.get(self.focus) else {
            return;
        };

        if !row.is_closeable() {
            self.refusal = Some(match &row.origin {
                PortOrigin::Service(service) => Msg::PortsRowFromService {
                    spec: row.spec(),
                    service: service.clone(),
                },
                PortOrigin::Direct => return,
            });

            return;
        }

        self.rows.remove(self.focus);

        // Onto the row that took its place, or the new last one where the
        // removed row was the last: a focus left past the end would draw no
        // bar and answer no keystroke.
        self.focus = self.focus.min(self.rows.len().saturating_sub(1));
    }

    /// Opens a cell of the focused row for editing.
    pub fn edit(&mut self, column: Column) {
        let Some(row) = self.rows.get(self.focus) else {
            return;
        };

        // The cell's own kind rather than the parameter's: a port is checked
        // as a port and a protocol against the two words this tool writes, so
        // the validation a cell shows is the validation the value will face.
        let (param, initial, offers) = match column {
            Column::Port => (
                Param::new("port", "Port", ParamKind::Port),
                row.port.clone(),
                Vec::new(),
            ),
            Column::Protocol => (
                Param::new("protocol", "Protocol", ParamKind::Protocol).offering(PROTOCOLS),
                row.protocol.clone(),
                PROTOCOLS.iter().map(|word| (*word).to_owned()).collect(),
            ),
        };

        let mut field = Field::new(param.with_initial(initial));

        // Handed over here rather than declared and forgotten. `offering` says
        // what the parameter *is*; a field only steps through values something
        // has actually given it, which in a form is the pass that asks the
        // host. This list needs no host — it is the two words the front-ends
        // accept — so the cell supplies its own.
        if !offers.is_empty() {
            field.offer(offers);
        }

        self.editing = Some(Editing {
            row: self.focus,
            column,
            field,
        });
    }

    /// Writes the cell being edited back into its row and closes the editor.
    ///
    /// Refuses to close over a value that is not one, leaving the cell open
    /// with its verdict showing: a row committed empty would serialise to a
    /// spec like `/tcp`, which the parameter's validator rejects at a point
    /// where the operator can no longer see which row caused it.
    pub fn commit_cell(&mut self) -> bool {
        let Some(editing) = &self.editing else {
            return false;
        };

        if !editing.field.is_valid() {
            return false;
        }

        let value = editing.field.value();
        let (row, column) = (editing.row, editing.column);

        // Written first and undone if it collides, because whether a value
        // duplicates another row is a question about the row it would make
        // rather than about the value on its own — and the cell's own
        // validator, which is what `is_valid` above asked, cannot see the
        // other rows.
        let previous = match self.rows.get_mut(row) {
            Some(target) => match column {
                Column::Port => std::mem::replace(&mut target.port, value),
                Column::Protocol => std::mem::replace(&mut target.protocol, value),
            },
            None => return false,
        };

        if let Some(duplicate) = self.first_duplicate() {
            let spec = self.rows[duplicate].spec();

            // The typed value stays and the cell stays open. Reverting it was
            // the first attempt and is worse in two ways: on a row just added
            // the previous value is empty, so `443` colliding left `/tcp` and
            // the port the operator typed was simply gone — and even on an
            // existing row, taking back what somebody typed while telling them
            // it collided leaves them nothing to correct.
            //
            // What this does *not* do is close the editor, so the collision
            // cannot be walked away from silently: `refuses_to_submit` catches
            // it again if it somehow is.
            let _ = previous;

            self.refusal = Some(Msg::PortsRowDuplicate { spec });

            return false;
        }

        self.editing = None;

        true
    }

    /// Abandons the cell being edited, leaving the row as it was.
    pub fn discard_cell(&mut self) {
        self.editing = None;
    }

    /// Moves from the cell being edited to the next one.
    ///
    /// Port to protocol within a row, and protocol to the next row's port —
    /// which is the order the columns are read in, so `Tab` walks the table
    /// the way the eye does.
    pub fn edit_next_cell(&mut self) {
        let Some(editing) = &self.editing else {
            return;
        };

        let column = editing.column;

        if !self.commit_cell() {
            return;
        }

        match column {
            Column::Port => self.edit(Column::Protocol),
            Column::Protocol => {
                if self.focus + 1 < self.rows.len() {
                    self.focus += 1;
                    self.edit(Column::Port);
                }
            }
        }
    }

    /// The first row that could not be acted on, if any.
    ///
    /// Asked before the table submits, so a malformed row is caught while it
    /// is still on screen and can be pointed at. Returns the row rather than a
    /// verdict because refusing without saying which row is wrong leaves the
    /// operator to find it.
    pub fn first_invalid(&self) -> Option<usize> {
        self.rows.iter().position(|row| {
            ParamKind::Port.validate(&row.port).is_err()
                || ParamKind::Protocol.validate(&row.protocol).is_err()
        })
    }

    /// The first row naming a port another row already names, if any.
    ///
    /// **The pair rather than the number.** `443/tcp` and `443/udp` are two
    /// different rules and both are legitimate — SSH is TCP and WireGuard is
    /// UDP on adjacent numbers often enough that refusing the second would
    /// refuse a set an operator legitimately wants. What is duplicated is a
    /// rule, not a port.
    ///
    /// Answered separately from [`first_invalid`](Self::first_invalid) because
    /// the two are wrong in different ways: a malformed row is a value nobody
    /// finished typing, and a duplicate is two rows each of which is fine. The
    /// refusal has to say which it is.
    fn first_duplicate(&self) -> Option<usize> {
        self.rows.iter().enumerate().position(|(index, row)| {
            self.rows
                .iter()
                .take(index)
                .any(|earlier| earlier.spec() == row.spec())
        })
    }

    /// The row standing between the table and a submission, and why.
    ///
    /// Both refusals in one place, because the caller's job is to point at a
    /// row rather than to know which kinds of wrong there are.
    pub fn refuses_to_submit(&self) -> Option<(usize, Msg)> {
        if let Some(row) = self.first_invalid() {
            return Some((row, Msg::PortsRowIncomplete));
        }

        // Reachable even though `commit_cell` refuses one: a table opened on a
        // host whose front-end already listed the same spec twice arrives here
        // with a duplicate nobody typed.
        self.first_duplicate().map(|row| {
            (
                row,
                Msg::PortsRowDuplicate {
                    spec: self.rows[row].spec(),
                },
            )
        })
    }

    /// Puts the focus on a row and says why, for a submission that was refused.
    pub fn refuse(&mut self, row: usize, reason: Msg) {
        self.focus = row;
        self.refusal = Some(reason);
    }

    /// Whether the focused cell offers a closed set of values to step through.
    pub fn focused_offers_options(&self) -> bool {
        self.editing
            .as_ref()
            .is_some_and(|editing| !editing.field.options().is_empty())
    }

    /// Where this dialog is drawn inside the terminal.
    fn area(&self, terminal: Rect) -> Rect {
        // Measured from the rows, plus the blank row above the footer. The
        // ceiling keeps a host admitting forty ports from claiming the screen;
        // there is deliberately no floor, because a dialog taller than its
        // content is exactly the band of empty space this one had between its
        // table and its footer.
        let rows = (self.rows.len() as u16 + FOOTER_GAP).min(MAX_VISIBLE_ROWS);

        let refusal = if self.refusal.is_some() {
            REFUSAL_ROWS
        } else {
            0
        };

        layout::centred(DIALOG_WIDTH, CHROME_ROWS + rows + refusal, terminal)
    }

    /// Draws the dialog centred over the interface.
    ///
    /// `&mut` for the reason the form's is: the cell being edited recomputes
    /// its own scroll window as it is drawn, which is a write.
    pub fn render(&mut self, frame: &mut Frame, lang: Lang) {
        let area = self.area(frame.area());

        // Clear first, or the interface underneath shows through.
        frame.render_widget(Clear, area);

        let block = layout::framed(
            style::DIALOG_BORDER_INPUT,
            Span::styled(format!(" {} ", self.title), style::EMPHASIS),
        )
        .title_top(
            Line::from(Span::styled(
                lang.render(&Msg::PortsOpenCount {
                    count: self.rows.len(),
                }),
                style::BLOCK_SUBTITLE,
            ))
            .right_aligned(),
        )
        .title_bottom(Line::from(self.footer(lang)));

        let inner = block.inner(area);

        frame.render_widget(block, area);

        self.render_rows(frame, inner, lang);
    }

    /// The key hints along the bottom of the frame.
    ///
    /// Different keys in the two states, because they mean different things:
    /// `d` deletes a row while navigating and types a letter while editing,
    /// and a footer naming both at once would be wrong half the time.
    fn footer(&self, lang: Lang) -> Vec<Span<'static>> {
        if self.is_editing() {
            return style::key_hint("Enter", &lang.render(&Msg::PortsKeyCommit))
                .into_iter()
                .chain(style::key_hint("Tab", &lang.render(&Msg::PortsKeyNextCell)))
                .chain(style::key_hint("Esc", &lang.render(&Msg::PortsKeyDiscard)))
                .collect();
        }

        style::key_hint("a", &lang.render(&Msg::PortsKeyAdd))
            .into_iter()
            .chain(style::key_hint("d", &lang.render(&Msg::PortsKeyRemove)))
            .chain(style::key_hint("Enter", &lang.render(&Msg::PortsKeyEdit)))
            .chain(style::key_hint("Tab", &lang.render(&Msg::PortsKeyApply)))
            // The same guard the form draws, for the same reason: a table with
            // edited rows asks twice, and a first `Esc` that changes nothing on
            // screen invites the second press that discards them.
            .chain(style::key_hint(
                "Esc",
                &lang.render(&if self.cancel_armed {
                    Msg::KeyCancelArmed
                } else {
                    Msg::FormKeyCancel
                }),
            ))
            .collect()
    }

    /// Draws the table's rules, its heading, its rows, and any refusal.
    fn render_rows(&mut self, frame: &mut Frame, area: Rect, lang: Lang) {
        let area = layout::inset(area, 0, 1);

        // The table keeps its own height and the refusal follows it, rather
        // than the message being pinned to the bottom of the dialog. Pinned,
        // it floated three rows under a short table with nothing between them,
        // reading as a message about something else on screen.
        let table_area = area;

        // Top rule, heading, mid rule, rows, bottom rule. Split off one at a
        // time from the top, so a dialog squeezed narrower than its content
        // draws fewer rows rather than drawing them over each other.
        let Some((top, rest)) = split_off_first_row(table_area) else {
            return;
        };
        let Some((heading, rest)) = split_off_first_row(rest) else {
            return;
        };
        let Some((middle, rest)) = split_off_first_row(rest) else {
            return;
        };

        // The closing rule sits under the last row rather than at the foot of
        // whatever room the dialog has. A table floored at `MIN_VISIBLE_ROWS`
        // is taller than its contents by design — so a host admitting one port
        // still has somewhere to put the row `a` adds — and closing at the
        // bottom of that space left the rule hanging three lines below the
        // last port, which reads as a table that failed to finish drawing.
        let drawn_rows = u16::try_from(self.rows.len())
            .unwrap_or(u16::MAX)
            .min(rest.height.saturating_sub(1));

        let rows_area = Rect {
            height: drawn_rows,
            ..rest
        };

        let bottom = Rect {
            y: rest.y + drawn_rows,
            height: 1,
            ..rest
        };

        // One cell short of the area, so the closing rule lands inside the
        // frame rather than on it. `List` pads its items to the full width,
        // which is why the rows themselves need no such allowance and this
        // does.
        let width = (table_area.width as usize).saturating_sub(1);

        frame.render_widget(rule(width, Corner::Top), top);
        frame.render_widget(rule(width, Corner::Middle), middle);
        frame.render_widget(rule(width, Corner::Bottom), bottom);

        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                cells(
                    width,
                    "",
                    &lang.render(&Msg::PortsColumnPort),
                    &lang.render(&Msg::PortsColumnProtocol),
                    &lang.render(&Msg::PortsColumnSource),
                ),
                style::BLOCK_SUBTITLE,
            ))),
            heading,
        );

        self.render_list(frame, rows_area, width, lang);

        if let Some(refusal) = &self.refusal {
            // Directly under the rule that closes the table, so the message
            // reads as being about the row above it.
            let message_area = Rect {
                y: bottom.y + 1,
                height: REFUSAL_ROWS.min(area.height.saturating_sub(bottom.y + 1 - area.y)),
                ..area
            };

            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    lang.render(refusal),
                    style::OUTPUT_WARN,
                )))
                // Wrapped rather than truncated. A refusal names a service and
                // says what removing the port does not do, which is longer than
                // the dialog is wide — and a sentence cut at the border reads
                // as a rendering bug rather than as the end of the explanation.
                .wrap(ratatui::widgets::Wrap { trim: false }),
                layout::inset(message_area, GUTTER_WIDTH as u16, 0),
            );
        }
    }

    /// Draws the rows themselves, and places the cursor where a cell is open.
    fn render_list(&mut self, frame: &mut Frame, area: Rect, width: usize, lang: Lang) {
        let editing = self.editing.as_mut().map(|editing| {
            (
                editing.row,
                editing.column,
                editing.field.visible(PORT_WIDTH - 1),
            )
        });

        let items: Vec<ListItem> = self
            .rows
            .iter()
            .enumerate()
            .map(|(index, row)| {
                let focused = index == self.focus;

                // The cell being edited shows the editor's own view of itself,
                // scrolled to the cursor, rather than the row's stored value.
                let (port, protocol) = match &editing {
                    Some((editing_row, Column::Port, (text, _))) if *editing_row == index => {
                        (text.clone(), row.protocol.clone())
                    }
                    Some((editing_row, Column::Protocol, (text, _))) if *editing_row == index => {
                        (row.port.clone(), text.clone())
                    }
                    _ => (row.port.clone(), row.protocol.clone()),
                };

                let source = match &row.origin {
                    PortOrigin::Service(service) => lang.render(&Msg::PortsSourceService {
                        service: service.clone(),
                    }),
                    PortOrigin::Direct if row.added => lang.render(&Msg::PortsSourceAdded),
                    PortOrigin::Direct => String::new(),
                };

                let text = cells(
                    width,
                    if focused { FOCUS_BAR } else { "" },
                    &port,
                    &protocol,
                    &source,
                );

                // Dimmed where the row is one this tool will not close, so the
                // refusal is visible before the key is pressed rather than
                // only afterwards — and the word in the source column says the
                // same thing, since no signal here is carried by colour alone.
                ListItem::new(Line::from(Span::styled(
                    text,
                    if row.is_closeable() {
                        style::NORMAL
                    } else {
                        style::DISABLED
                    },
                )))
            })
            .collect();

        let mut state = ListState::default().with_selected(Some(self.focus));

        frame.render_stateful_widget(List::new(items), area, &mut state);

        // The terminal cursor only exists while a cell is open. Navigating, the
        // focus bar is what says where the operator is — which is why this is
        // the one dialog that draws no cursor most of the time.
        if let Some((row, column, (_, cursor))) = editing {
            // Counted through the same pieces `cells` lays out: the gutter, the
            // rule opening the row, and the space after it. Derived rather than
            // written as a number, so a column that changes width moves the
            // cursor with it.
            let column_offset = GUTTER_WIDTH
                + 2
                + match column {
                    Column::Port => 0,
                    Column::Protocol => PORT_WIDTH + 1,
                };

            // Relative to the top of the list, and only where the row is
            // actually on screen: a cursor placed against a scrolled-away row
            // would sit on whatever is drawn there instead.
            let placed = u16::try_from(row.saturating_sub(state.offset()))
                .ok()
                .filter(|offset| *offset < area.height)
                .zip(u16::try_from(column_offset + cursor).ok());

            if let Some((offset, cursor)) = placed {
                frame.set_cursor_position((area.x + cursor, area.y + offset));
            }
        }
    }
}

/// Which of the table's three horizontal rules is being drawn.
///
/// They differ only in the junction where a column rule meets them, and that
/// junction is the whole point: a `┬` says the line below is divided and a `┴`
/// says the division ends here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Corner {
    Top,
    Middle,
    Bottom,
}

/// One horizontal rule of the table, with its column junctions.
///
/// Built from the same widths the cells are, so a rule cannot drift from the
/// columns it is dividing — the failure that turns a table back into text that
/// happens to have lines through it.
fn rule(width: usize, corner: Corner) -> Paragraph<'static> {
    let (left, junction, right) = match corner {
        Corner::Top => ('┌', '┬', '┐'),
        Corner::Middle => ('├', '┼', '┤'),
        Corner::Bottom => ('└', '┴', '┘'),
    };

    let mut line = String::new();

    // The gutter sits outside the table, so the focus bar has somewhere to go
    // that is not inside a cell.
    line.push_str(&" ".repeat(GUTTER_WIDTH));
    line.push(left);
    line.push_str(&"─".repeat(PORT_WIDTH));
    line.push(junction);
    line.push_str(&"─".repeat(PROTOCOL_WIDTH));
    line.push(junction);

    // The last column takes whatever is left, so the table reaches the same
    // right-hand edge whatever the terminal is clamped to. Counted through the
    // pieces already pushed rather than re-derived: `line` is what was drawn,
    // and an arithmetic second opinion is what put the closing rule a cell
    // past the frame.
    let drawn = line.chars().count();
    line.push_str(&"─".repeat(width.saturating_sub(drawn + 1)));
    line.push(right);

    Paragraph::new(Line::from(Span::styled(line, style::TREE_GUIDE)))
}

/// One row of the table, gutter and column rules included.
///
/// Values are padded to the column rather than separated by spaces, so a
/// two-character port and a five-character one start at the same column — which
/// is the difference between a table and three lists side by side.
///
/// `width` closes the row on the right. A table ruled down both sides and open
/// along one of them reads as a rendering fault rather than as a style.
fn cells(width: usize, gutter: &str, port: &str, protocol: &str, source: &str) -> String {
    let mut line = format!(
        "{gutter:gutter_width$}{COLUMN_RULE} {port:port_width$}{COLUMN_RULE} \
         {protocol:protocol_width$}{COLUMN_RULE} {source}",
        gutter_width = GUTTER_WIDTH,
        // One cell of the width goes to the space after the rule, so the value
        // does not touch it.
        port_width = PORT_WIDTH - 1,
        protocol_width = PROTOCOL_WIDTH - 1,
    );

    let drawn = line.chars().count();

    line.push_str(&" ".repeat(width.saturating_sub(drawn + 1)));
    line.push(COLUMN_RULE);

    line
}

/// Splits the first row off an area, for a header that does not scroll.
///
/// `None` where there is no room for both, so a dialog squeezed to nothing
/// draws no header over no rows rather than panicking on the arithmetic.
fn split_off_first_row(area: Rect) -> Option<(Rect, Rect)> {
    if area.height < 2 {
        return None;
    }

    Some((
        Rect { height: 1, ..area },
        Rect {
            y: area.y + 1,
            height: area.height - 1,
            ..area
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a stock RHEL host looks like: one port named directly, and SSH
    /// admitted by a service.
    fn admitted() -> Vec<AllowedPort> {
        vec![
            AllowedPort::direct("51820/udp"),
            AllowedPort {
                spec: "22/tcp".to_owned(),
                origin: PortOrigin::Service("ssh".to_owned()),
            },
        ]
    }

    #[test]
    fn the_table_opens_on_what_the_host_admits() {
        let table = PortTable::new("Manage ports", &admitted());

        assert_eq!(table.value(), "51820/udp 22/tcp");
        assert_eq!(table.opened_on(), "51820/udp 22/tcp");
        assert!(table.is_untouched());
    }

    #[test]
    fn a_row_a_service_admits_cannot_be_removed() {
        // The refusal the whole table exists to make visible. Accepting the
        // keystroke would let the operator leave believing SSH was closed.
        let mut table = PortTable::new("Manage ports", &admitted());

        table.focus_next(); // onto the service row

        table.remove_row();

        assert_eq!(
            table.value(),
            "51820/udp 22/tcp",
            "the row must survive the keystroke"
        );
        assert!(
            table.refusal.is_some(),
            "and the refusal must say why it did"
        );
    }

    #[test]
    fn a_removed_row_leaves_the_declared_set() {
        let mut table = PortTable::new("Manage ports", &admitted());

        table.remove_row(); // the directly-named one

        assert_eq!(table.value(), "22/tcp");
        assert!(!table.is_untouched());
    }

    #[test]
    fn removing_the_last_row_leaves_the_focus_on_a_row_that_exists() {
        // A focus left past the end draws no bar and answers no keystroke.
        let mut table = PortTable::new("Manage ports", &[AllowedPort::direct("80/tcp")]);

        table.remove_row();

        assert_eq!(table.value(), "");
        assert_eq!(table.focus, 0);
    }

    #[test]
    fn an_added_row_is_editable_and_reaches_the_set() {
        let mut table = PortTable::new("Manage ports", &[]);

        table.add_row();

        assert!(table.is_editing(), "a new row opens for editing");

        let field = table.editing_field().expect("the cell must be open");

        for character in "8080".chars() {
            field.insert(character);
        }

        assert!(table.commit_cell());
        assert_eq!(table.value(), "8080/tcp");
    }

    #[test]
    fn an_empty_row_does_not_commit() {
        // A row committed empty would serialise to `/tcp`, which the
        // parameter's validator rejects somewhere the operator can no longer
        // see which row caused it.
        let mut table = PortTable::new("Manage ports", &[]);

        table.add_row();

        assert!(!table.commit_cell(), "an empty port must not commit");
        assert!(table.is_editing(), "and the cell must stay open");
    }

    #[test]
    fn a_table_holding_an_incomplete_row_does_not_submit() {
        let mut table = PortTable::new("Manage ports", &[]);

        table.add_row();
        table.discard_cell();

        assert_eq!(table.first_invalid(), Some(0));
    }

    #[test]
    fn tab_walks_from_the_port_to_the_protocol() {
        let mut table = PortTable::new("Manage ports", &[AllowedPort::direct("80/tcp")]);

        table.edit(Column::Port);
        table.edit_next_cell();

        let editing = table.editing.as_ref().expect("the protocol must be open");

        assert_eq!(editing.column, Column::Protocol);
        assert_eq!(editing.row, 0);
    }

    #[test]
    fn a_discarded_cell_leaves_the_row_as_it_was() {
        let mut table = PortTable::new("Manage ports", &[AllowedPort::direct("80/tcp")]);

        table.edit(Column::Port);

        let field = table.editing_field().expect("the cell must be open");
        field.insert('9');

        table.discard_cell();

        assert_eq!(table.value(), "80/tcp");
    }

    #[test]
    fn the_protocol_cell_offers_the_two_words_this_tool_writes() {
        let mut table = PortTable::new("Manage ports", &[AllowedPort::direct("80/tcp")]);

        table.edit(Column::Protocol);

        assert!(table.focused_offers_options());
    }

    /// Draws the table and returns the screen as lines, for reading.
    /// Sized off this dialog's own width rather than the shared one, which is
    /// narrower: a terminal that clamps the dialog draws a different table
    /// from the one under test, and the assertions would be about the
    /// clamping.
    fn drawn(table: &mut PortTable) -> Vec<String> {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(DIALOG_WIDTH + 12, 30))
                .expect("the test backend must build");

        terminal
            .draw(|frame| table.render(frame, Lang::En))
            .expect("the table must draw");

        let buffer = terminal.backend().buffer().clone();

        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect()
    }

    #[test]
    fn the_table_draws_a_row_per_port_with_its_source() {
        let mut table = PortTable::new("Manage ports", &admitted());

        let screen = drawn(&mut table).join("\n");

        assert!(screen.contains("PORT"), "{screen}");
        assert!(screen.contains("PROTOCOL"), "{screen}");
        assert!(screen.contains("51820"), "{screen}");
        assert!(
            screen.contains("service ssh"),
            "the row a service admits must say so on screen, not only in a \
             refusal after the key is pressed: {screen}"
        );
    }

    #[test]
    fn there_is_no_terminal_cursor_until_a_cell_is_open() {
        // The invariant that lets this dialog place a cursor at all: the form
        // always has a focused field and always draws one, while here the
        // focus bar says where the operator is and the cursor means "this cell
        // is taking characters".
        let mut table = PortTable::new("Manage ports", &admitted());

        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(DIALOG_WIDTH + 12, 20))
                .expect("the test backend must build");

        // Asked of the backend rather than of the frame: the terminal hides the
        // cursor for a frame that asked for none, and that flag is the thing an
        // operator actually sees.
        terminal
            .draw(|frame| table.render(frame, Lang::En))
            .expect("the table must draw");

        assert!(
            !terminal.backend().cursor_visible(),
            "navigating draws no cursor"
        );

        table.edit(Column::Port);

        terminal
            .draw(|frame| table.render(frame, Lang::En))
            .expect("the table must draw");

        assert!(
            terminal.backend().cursor_visible(),
            "an open cell draws one"
        );
    }

    #[test]
    fn the_table_closes_under_its_last_row() {
        // Found by dumping the screen rather than by an assertion: the closing
        // rule was pinned to the foot of the dialog, which is taller than the
        // rows by design, so it hung three lines below the last port and read
        // as a table that failed to finish drawing.
        let mut table = PortTable::new("Manage ports", &admitted());

        let screen = drawn(&mut table);

        let last_row = screen
            .iter()
            .position(|line| line.contains("service ssh"))
            .expect("the last port must be drawn");

        assert!(
            screen[last_row + 1].contains('└'),
            "the rule must close directly under the last row:\n{}",
            screen.join("\n")
        );
    }

    #[test]
    fn every_row_is_ruled_on_both_sides() {
        // A table ruled down one side and open along the other reads as a
        // rendering fault rather than as a style — and the right-hand rule sat
        // a cell outside the frame until the width was counted through what
        // had actually been drawn rather than derived a second time.
        let mut table = PortTable::new("Manage ports", &admitted());

        let screen = drawn(&mut table);

        for line in screen.iter().filter(|line| line.contains("51820")) {
            let rules = line.matches(COLUMN_RULE).count();

            assert!(
                rules >= 4,
                "a row needs three column rules and a closing one: {line}"
            );
        }
    }

    #[test]
    fn a_refusal_is_wrapped_under_the_table_rather_than_cut_at_the_frame() {
        // Also found by reading a dump, twice: the message first inherited an
        // area with no gutter and ran into the border ending mid-word, and
        // then, pinned to the bottom of the dialog, floated three rows below
        // the table with nothing between them.
        let mut table = PortTable::new("Manage ports", &admitted());

        table.focus_next();
        table.remove_row();

        let screen = drawn(&mut table);
        let joined = screen.join("\n");

        assert!(
            joined.contains("does not undo"),
            "the whole sentence must be on screen:\n{joined}"
        );

        let closing = screen
            .iter()
            .position(|line| line.contains('└'))
            .expect("the table must close");

        assert!(
            screen[closing + 1].contains("22/tcp is admitted"),
            "and sit directly under the table it is about:\n{joined}"
        );
    }

    #[test]
    fn a_refusal_does_not_outlive_the_keystroke_it_belongs_to() {
        // Otherwise it reads as an answer to whatever the operator did next.
        let mut table = PortTable::new("Manage ports", &admitted());

        table.focus_next();
        table.remove_row();

        assert!(table.refusal.is_some(), "the refusal must be raised");

        table.add_row();

        assert!(
            table.refusal.is_none(),
            "and cleared by the next thing the operator does"
        );
    }

    #[test]
    fn the_dialog_is_wider_than_the_shared_floor() {
        // The one dialog here that is, and deliberately: the shared 72 is a
        // floor set by the parameter form's footer, and every other dialog's
        // content is prose that reads worse the wider it gets. This one's is a
        // table, whose columns need room to be columns.
        let table = PortTable::new("Manage ports", &admitted());

        let area = table.area(Rect {
            x: 0,
            y: 0,
            width: DIALOG_WIDTH + 12,
            height: 30,
        });

        assert_eq!(area.width, DIALOG_WIDTH);
        assert!(
            area.width > layout::DIALOG_WIDTH,
            "wider than the shared floor, which is the whole point"
        );
    }

    #[test]
    fn the_dialog_grows_with_its_rows_and_no_further() {
        // Measured from the content, like every other modal here. A floor was
        // the first attempt and is what left a one-port table with a band of
        // empty space between its closing rule and the footer — the dialog was
        // as tall as it had been told to be rather than as tall as it drew.
        let one = PortTable::new("Manage ports", &[AllowedPort::direct("80/tcp")]);
        let several = PortTable::new("Manage ports", &admitted());

        let terminal = Rect {
            x: 0,
            y: 0,
            width: DIALOG_WIDTH + 12,
            height: 30,
        };

        assert_eq!(
            several.area(terminal).height - one.area(terminal).height,
            (several.rows.len() - one.rows.len()) as u16,
            "a row more of content is a row more of dialog, and nothing else"
        );
    }

    #[test]
    fn adding_a_row_grows_the_dialog_by_exactly_that_row() {
        // The dialog is measured from its content, so it does move — by one
        // row, which is the row that appeared. What it must not do is jump:
        // an earlier version floored the height, so the first `a` on a
        // one-port host changed nothing and the seventh moved everything.
        let mut table = PortTable::new("Manage ports", &[AllowedPort::direct("80/tcp")]);

        let terminal = Rect {
            x: 0,
            y: 0,
            width: DIALOG_WIDTH + 12,
            height: 30,
        };

        let before = table.area(terminal).height;

        table.add_row();

        assert_eq!(table.area(terminal).height, before + 1);
    }

    #[test]
    fn the_same_rule_cannot_be_listed_twice() {
        // Two identical rows admit the port exactly as one does, so the second
        // is a keystroke that means nothing — refused where the operator can
        // still see which row caused it.
        let mut table = PortTable::new("Manage ports", &[AllowedPort::direct("443/tcp")]);

        table.add_row();

        let field = table.editing_field().expect("the cell must be open");
        for character in "443".chars() {
            field.insert(character);
        }

        assert!(!table.commit_cell(), "the duplicate must be refused");
        assert!(table.refusal.is_some(), "and say so");
        assert!(
            table.is_editing(),
            "leaving the cell open so it can be corrected"
        );
    }

    #[test]
    fn the_same_port_on_the_other_protocol_is_a_different_rule() {
        // 443/tcp and 443/udp are two rules and both are legitimate — SSH is
        // TCP and WireGuard UDP on adjacent numbers often enough that refusing
        // the second would refuse a set an operator legitimately wants.
        let mut table = PortTable::new("Manage ports", &[AllowedPort::direct("443/tcp")]);

        table.add_row();

        let field = table.editing_field().expect("the port cell must be open");
        for character in "443".chars() {
            field.insert(character);
        }

        // The port alone still collides while the protocol matches...
        assert!(!table.commit_cell());

        table.edit(Column::Protocol);

        let field = table
            .editing_field()
            .expect("the protocol cell must be open");
        field.clear_before_cursor();
        for character in "udp".chars() {
            field.insert(character);
        }

        assert!(
            table.commit_cell(),
            "...and stops colliding once the protocol differs"
        );
        assert_eq!(table.value(), "443/tcp 443/udp");
    }

    #[test]
    fn holding_the_add_key_does_not_stack_empty_rows() {
        // Each would have to be filled or removed before the table could
        // submit, and the refusal that stops it names only the first.
        let mut table = PortTable::new("Manage ports", &[]);

        table.add_row();
        table.add_row();
        table.add_row();

        assert_eq!(table.rows.len(), 1, "one unfinished row at a time");
    }

    #[test]
    fn a_table_carrying_a_duplicate_refuses_to_submit() {
        // Reachable even though `commit_cell` refuses one: a host whose
        // front-end already listed the same spec twice opens a table with a
        // duplicate nobody typed.
        let table = PortTable::new(
            "Manage ports",
            &[
                AllowedPort::direct("443/tcp"),
                AllowedPort::direct("443/tcp"),
            ],
        );

        let (row, _) = table
            .refuses_to_submit()
            .expect("a duplicate must stop the submission");

        assert_eq!(row, 1, "and point at the second of the pair");
    }

    #[test]
    fn a_table_nobody_edited_is_untouched() {
        // What lets `Esc` close without demanding a second press.
        let mut table = PortTable::new("Manage ports", &admitted());

        table.focus_next();
        table.focus_previous();

        assert!(table.is_untouched());
    }
}
