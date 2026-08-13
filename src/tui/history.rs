//! Reading back what this tool copied aside, and putting one of it back.
//!
//! The index records every configuration change; without something to read it
//! the record is a file nobody opens. This is that something: a list of what
//! was changed, when, and by which task, with any one of them restorable.
//!
//! **Why a view rather than two tasks.** A task reports into the output pane,
//! which is a transcript: it scrolls, it is appended to by whatever runs next,
//! and nothing in it can be selected. Choosing among ten recorded states of one
//! file is a selection, and a transcript cannot express one. The tree also
//! cannot hold these as rows — it is built once at startup from `tasks::tree()`
//! and these come from a file that changes while the interface is open.
//!
//! **Why the task's name is shown beside the time.** Ten timestamps for one
//! path is a list of guesses unless something says what each one is. `ssh.harden
//! · 09 Aug 14:22` is a state an operator recognises; `09 Aug 14:22` alone asks
//! them to remember what they were doing.
//!
//! Semi-modal, like [`super::search`]: it takes the keyboard and draws over the
//! tree, and `Esc` closes it having changed nothing. Restoring is the one thing
//! it does, and that goes through the same confirmation and the same
//! verification window as any other change that can sever the session.

use ratatui::Frame;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, List, ListItem, ListState};

use super::{layout, style};
use crate::backend::backup_index::BackupRecord;
use crate::i18n::{Lang, Msg};

/// Width of the overlay, in columns.
///
/// The width every modal shares. Two dialogs opened in one session at two
/// widths read as an interface that has not decided.
const WIDTH: u16 = layout::DIALOG_WIDTH;

/// Height of the overlay, in rows.
const HEIGHT: u16 = 16;

/// The recorded changes, and which one the cursor is on.
///
/// Loaded once when the view opens rather than watched: the file is appended to
/// by this process alone, and re-reading it per frame would put the executor in
/// the path of a keystroke — the rule the probe and the form suggestions both
/// follow.
pub struct History {
    /// Records, newest first.
    ///
    /// Reversed from the file's own order, which is oldest first because it is
    /// appended to. What an operator wants is what happened last.
    records: Vec<BackupRecord>,
    /// Which record the cursor is on.
    selected: usize,
}

impl History {
    /// Opens a view over records already read from the host.
    ///
    /// Takes them rather than reading them, so that this type needs no executor
    /// and stays testable without one — the shape `Search` uses for the tree.
    pub fn new(mut records: Vec<BackupRecord>) -> Self {
        records.reverse();

        Self {
            records,
            selected: 0,
        }
    }

    /// Whether anything was recorded at all.
    ///
    /// A host where this tool has never changed a file has an empty index, and
    /// that is an answer rather than a failure — the view says so instead of
    /// drawing an empty list that looks like a bug.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The record under the cursor.
    pub fn selected(&self) -> Option<&BackupRecord> {
        self.records.get(self.selected)
    }

    /// Moves the cursor down one row, stopping at the last.
    ///
    /// Stops rather than wrapping, the same as the tree: a list that wraps
    /// makes "am I at the end" a question the operator has to test for.
    pub fn select_next(&mut self) {
        let last = self.records.len().saturating_sub(1);

        self.selected = self.selected.saturating_add(1).min(last);
    }

    /// Moves the cursor up one row, stopping at the first.
    pub fn select_previous(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// Moves the cursor to the newest record.
    pub fn select_first(&mut self) {
        self.selected = 0;
    }

    /// Moves the cursor to the oldest record.
    pub fn select_last(&mut self) {
        self.selected = self.records.len().saturating_sub(1);
    }

    /// How many records there are, for the title.
    pub fn len(&self) -> usize {
        self.records.len()
    }
}

/// Draws the history over whatever is beneath it.
pub fn render(frame: &mut Frame, history: &History, lang: Lang) {
    let area = layout::centred(WIDTH, HEIGHT, frame.area());

    frame.render_widget(Clear, area);

    let block = layout::framed(
        style::border(true),
        Span::styled(
            lang.render(&Msg::HistoryTitle {
                count: history.len(),
            }),
            style::PANE_TITLE,
        ),
    );

    // Nothing recorded is a sentence rather than an empty list. An empty list
    // in a bordered box looks like a view that failed to load, and the two
    // deserve different reactions.
    if history.is_empty() {
        let empty = ratatui::widgets::Paragraph::new(lang.render(&Msg::HistoryEmpty))
            .block(block)
            .wrap(ratatui::widgets::Wrap { trim: true });

        frame.render_widget(empty, area);

        return;
    }

    let rows: Vec<ListItem> = history
        .records
        .iter()
        .map(|record| ListItem::new(row(record, area.width.saturating_sub(2) as usize)))
        .collect();

    let mut state = ListState::default();
    state.select(Some(history.selected));

    let list = List::new(rows)
        .block(block)
        .highlight_style(style::SELECTION_FOCUSED);

    frame.render_stateful_widget(list, area, &mut state);
}

/// One record as a row.
///
/// The task's name comes first because it is what identifies the state: ten
/// timestamps for one path are indistinguishable without it. The path follows,
/// and the time last — an operator scanning for "the hardening I did" reads
/// left to right and stops at the first column.
fn row(record: &BackupRecord, width: usize) -> Line<'static> {
    let when = readable_time(&record.at);
    let head = format!("{} · {when}  ", record.task);
    let room = width.saturating_sub(head.chars().count());

    Line::from(vec![
        Span::styled(head, style::NORMAL),
        // The path is what the row is *about*, and it is the part that runs
        // long — `/etc/ssh/sshd_config` fits, a Caddyfile under a deep prefix
        // may not. Truncated from the head, since a path is identified by
        // where it ends.
        Span::styled(truncate_head(&record.path, room), style::BLOCK_SUBTITLE),
    ])
}

/// A stamp as a person reads it.
///
/// The stored form is `20260809T142203Z`, which sorts and is filename-safe and
/// is not something to hand to somebody deciding what to restore. Rendered here
/// rather than in the catalogue: it is a rearrangement of digits, and the
/// month names are the one part that would need translating — which is why
/// there are none.
fn readable_time(stamp: &str) -> String {
    // Anything not of the expected shape is shown as it is rather than sliced
    // into nonsense: a record written by a future version is still a record,
    // and its own timestamp is the honest thing to print.
    //
    // The shape is checked rather than the length, because the slicing below
    // indexes *bytes* and `len()` counts them too — so a sixteen-byte stamp
    // holding a multibyte character passed this guard and then panicked on a
    // boundary inside that character. Measured: `000é0000000000Z` is sixteen
    // bytes, ends in `Z`, and `&stamp[0..4]` splits the `é`. Thirty-nine such
    // strings exist for one two-byte character alone.
    //
    // It is reachable rather than theoretical. The stamp comes from
    // `/var/lib/initd/backups.jsonl`, and `BackupRecord::from_line` matches its
    // `task` and `service` fields against what this build knows while `at` is
    // taken as it is — the same trust boundary the index documents, applied to
    // two fields of three. A panic here takes the interface down while a task's
    // history is being read, on a tool whose whole promise is a way back.
    //
    // Requiring digits and the `T` makes every boundary below an ASCII one by
    // construction, which is what the slicing already assumed.
    let shaped = stamp.len() == 16
        && stamp.ends_with('Z')
        && stamp.as_bytes()[..8].iter().all(u8::is_ascii_digit)
        && stamp.as_bytes()[8] == b'T'
        && stamp.as_bytes()[9..15].iter().all(u8::is_ascii_digit);

    if !shaped {
        return stamp.to_owned();
    }

    format!(
        "{}-{}-{} {}:{}",
        &stamp[0..4],
        &stamp[4..6],
        &stamp[6..8],
        &stamp[9..11],
        &stamp[11..13],
    )
}

/// Cuts a path from its head, keeping the end.
///
/// A path is identified by where it ends: `…/ssh/sshd_config` says what the row
/// is about where `/etc/ssh/sshd…` does not.
///
/// Measured in cells rather than in characters, which is what this counted
/// before. The two agree only while every character is one cell wide, and the
/// paths here come out of `backups.jsonl` — a file whose contents are whatever
/// the administrator's filesystem holds. A wide character made the row overrun
/// its width, and since the ellipsis is prepended last it was the ellipsis that
/// the pane clipped. `render::truncate_head` documents the same reasoning; that
/// one frames its result for a border, which is why this is not a call to it.
fn truncate_head(path: &str, room: usize) -> String {
    if super::render::cells(path) <= room {
        return path.to_owned();
    }

    // One cell is reserved for the ellipsis, then characters are kept from the
    // back while they fit whole: a wide character cannot be half included.
    let budget = room.saturating_sub(1);
    let mut kept = String::new();
    let mut used = 0;

    for character in path.chars().rev() {
        let next = used + super::render::cells(character.encode_utf8(&mut [0; 4]));

        if next > budget {
            break;
        }

        kept.insert(0, character);
        used = next;
    }

    if kept.is_empty() {
        return String::new();
    }

    format!("…{kept}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(task: &'static str, at: &str, path: &str) -> BackupRecord {
        BackupRecord {
            task,
            path: path.to_owned(),
            copy: format!("/var/lib/initd/backups/x.{at}"),
            at: at.to_owned(),
            sha256_before: "a".repeat(64),
            sha256_after: "b".repeat(64),
            service: "ssh.service",
        }
    }

    #[test]
    fn the_newest_change_is_the_one_the_cursor_starts_on() {
        // The file is appended to, so it reads oldest first; what an operator
        // opening this wants is what happened last.
        let history = History::new(vec![
            record("ssh.harden", "20260101T090000Z", "/etc/ssh/sshd_config"),
            record(
                "ssh.change-port",
                "20260809T142203Z",
                "/etc/ssh/sshd_config",
            ),
        ]);

        assert_eq!(
            history.selected().map(|record| record.task),
            Some("ssh.change-port")
        );
    }

    #[test]
    fn a_host_with_no_records_says_so_rather_than_showing_an_empty_list() {
        // An empty list inside a bordered box reads as a view that failed to
        // load. The two deserve different reactions, so they get different
        // renderings.
        assert!(History::new(Vec::new()).is_empty());
        assert!(History::new(Vec::new()).selected().is_none());
    }

    #[test]
    fn the_cursor_stops_at_both_ends() {
        // Stopping rather than wrapping, as the tree does: a list that wraps
        // makes "am I at the end" something the operator has to test for.
        let mut history = History::new(vec![
            record("ssh.harden", "20260101T090000Z", "/etc/ssh/sshd_config"),
            record(
                "ssh.change-port",
                "20260809T142203Z",
                "/etc/ssh/sshd_config",
            ),
        ]);

        history.select_previous();
        assert_eq!(
            history.selected().map(|record| record.task),
            Some("ssh.change-port"),
            "already at the newest"
        );

        history.select_next();
        history.select_next();
        assert_eq!(
            history.selected().map(|record| record.task),
            Some("ssh.harden"),
            "and stops at the oldest"
        );
    }

    #[test]
    fn a_stamp_is_rendered_for_reading_rather_than_for_sorting() {
        assert_eq!(readable_time("20260809T142203Z"), "2026-08-09 14:22");
    }

    #[test]
    fn a_stamp_of_another_shape_is_shown_as_it_is() {
        // A record written by a future version is still a record, and slicing
        // its timestamp into nonsense would be worse than printing it.
        assert_eq!(readable_time("whenever"), "whenever");
        assert_eq!(readable_time(""), "");
    }

    #[test]
    fn a_stamp_holding_a_multibyte_character_is_shown_rather_than_split() {
        // The guard measured `len()`, which counts bytes, while the formatting
        // below it indexes bytes too — so a sixteen-byte stamp carrying a
        // two-byte character reached the slicing and panicked on a boundary
        // inside it: "end byte index 4 is not a char boundary". Reproduced
        // against this function before the guard was changed.
        //
        // Reachable rather than theoretical: the value comes from
        // `backups.jsonl`, whose reader checks the task and service fields
        // against what this build knows and takes the timestamp as it is.
        for stamp in [
            "000\u{e9}0000000000Z", // splits [0..4]
            "00000\u{e9}00000000Z", // splits [4..6]
            "0000000\u{e9}000000Z", // splits [6..8]
            "00000000\u{e9}00000Z", // splits [9..11]
            "0000000000\u{e9}000Z", // splits [11..13]
        ] {
            assert_eq!(stamp.len(), 16, "the old guard admitted this");
            assert_eq!(
                readable_time(stamp),
                stamp,
                "a stamp that is not the shape asked for is printed as it is"
            );
        }
    }

    #[test]
    fn a_path_is_cut_from_its_head() {
        // `…/ssh/sshd_config` says what the row is about; `/etc/ssh/sshd…`
        // does not.
        // Ten cells of room, one of which the ellipsis takes: nine characters
        // of path survive.
        assert_eq!(truncate_head("/etc/ssh/sshd_config", 10), "…hd_config");
        assert_eq!(truncate_head("/etc/hosts", 40), "/etc/hosts");
    }

    #[test]
    fn a_wide_character_is_measured_by_the_cells_it_occupies() {
        // Counting characters overruns the row: these occupy two cells each, so
        // a path of five of them is ten cells wide and not five. The row is
        // drawn into a fixed width, and the overrun clipped the ellipsis — the
        // one character saying the head was dropped at all.
        let wide = "/等等等等等";

        assert_eq!(super::super::render::cells(&truncate_head(wide, 7)), 7);

        // And a path that fits is returned whole, measured the same way.
        assert_eq!(truncate_head("/等", 3), "/等");
    }
}
