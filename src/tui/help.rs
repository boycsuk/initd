//! The help overlay.
//!
//! The key bar shows what is available *here*; this shows everything, grouped
//! by where it applies. It is the answer to "what else can this do", which a
//! bar four hints wide cannot give.
//!
//! The movement keys scroll it; any other key closes it, including the one
//! that opened it. An overlay that has to be dismissed a particular way traps
//! whoever opened it by accident.
//!
//! It scrolls rather than dropping what will not fit, because the section
//! worth reading most — the keys that cannot be guessed from anywhere else —
//! is the one at the end.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use super::{layout, style};
use crate::i18n::{Lang, Msg};

/// Width the overlay is drawn at, before clamping to the terminal.
///
/// The width every modal shares. It was 70 beside the form's 72 and the
/// search's 64 — three sizes over one interface, each defensible alone and
/// none chosen against the others.
const WIDTH: u16 = layout::DIALOG_WIDTH;

/// Height the overlay is drawn at, before clamping.
///
/// Two rows short of the 24 the interface is measured against, so the frame
/// itself has somewhere to land: at exactly 24 the overlay filled the terminal
/// and its top border was drawn off the screen, leaving a list that appeared
/// to have no dialog around it. The list scrolls, so the rows given up cost
/// nothing that cannot be reached.
const HEIGHT: u16 = 22;

/// One group of bindings, as it appears in the overlay.
///
/// Titles and descriptions are [`Msg`]s rather than text, so the wording lives
/// in the catalogue with every other user-facing string. The table stays a
/// `const` because every message it names is payload-free — a variant carrying
/// a `String` could not appear in one.
///
/// The key glyphs stay literals. `Tab` and `↑ k` name keys on a keyboard
/// rather than words in a language, and translating them would describe a
/// keyboard the operator does not have.
struct Section {
    title: Msg,
    keys: &'static [(&'static str, Msg)],
}

/// Every binding the interface has, grouped by where it applies.
///
/// Stated here rather than derived from the key handlers: a handler says what
/// a key does, not what it is *for*, and the grouping is the part that makes a
/// list of forty bindings readable.
const SECTIONS: &[Section] = &[
    Section {
        title: Msg::HelpSectionAnywhere,
        keys: &[
            ("Tab", Msg::HelpMoveFocus),
            ("?", Msg::HelpThisHelp),
            ("q", Msg::HelpQuit),
        ],
    },
    Section {
        title: Msg::HelpSectionTree,
        keys: &[
            ("↑ k", Msg::HelpPreviousRow),
            ("↓ j", Msg::HelpNextRow),
            ("g G", Msg::HelpFirstLastRow),
            ("Enter", Msg::HelpOpenOrRun),
            ("/", Msg::HelpFind),
            ("Esc ← h", Msg::HelpBack),
        ],
    },
    Section {
        title: Msg::HelpSectionSearch,
        keys: &[
            // The glyph column here is a word rather than a key name, so it is
            // the one entry in it that the catalogue owns.
            ("", Msg::HelpFilter),
            ("↑ ↓", Msg::HelpBetweenResults),
            ("Enter", Msg::HelpGoToTask),
            ("Esc", Msg::HelpCloseSearch),
        ],
    },
    // Listed because this is when somebody most needs it: a task three minutes
    // in is exactly when `?` gets pressed, and the key bar that also shows
    // Ctrl-C is dropped on a terminal under 24 rows.
    Section {
        title: Msg::HelpSectionRunning,
        keys: &[
            ("Ctrl-C", Msg::HelpStopAfterCommand),
            ("↑ ↓", Msg::HelpScrollOutput),
            ("Tab", Msg::HelpFocusOutput),
        ],
    },
    Section {
        title: Msg::HelpSectionOutput,
        keys: &[
            ("↑ k / ↓ j", Msg::HelpScrollLine),
            ("PageUp/Down", Msg::HelpScrollPage),
            ("g", Msg::HelpOldestLine),
            ("G f", Msg::HelpNewestLine),
            ("y", Msg::HelpCopy),
        ],
    },
    Section {
        title: Msg::HelpSectionForms,
        keys: &[
            ("Tab", Msg::HelpNextField),
            ("Enter", Msg::HelpNextFieldOrSubmit),
            ("↑↓", Msg::HelpStepOptions),
            ("Ctrl-L", Msg::HelpListOptions),
            ("Ctrl-A/E", Msg::HelpFieldEnds),
            ("Ctrl-U/K", Msg::HelpClearAround),
            ("Ctrl-W", Msg::HelpDeleteWord),
            ("Esc", Msg::HelpCancelForm),
        ],
    },
    Section {
        title: Msg::HelpSectionConfirmation,
        keys: &[
            ("y", Msg::HelpApply),
            ("n Esc", Msg::HelpCancel),
            ("← →", Msg::HelpBetweenAnswers),
        ],
    },
    Section {
        title: Msg::HelpSectionLockout,
        keys: &[
            ("K", Msg::HelpKeep),
            ("R", Msg::HelpRevert),
            ("", Msg::HelpAutoRevert),
        ],
    },
];

/// The glyph shown for an entry whose key column is a word, not a key.
///
/// `(type)` and `(wait)` describe *doing* something rather than pressing a
/// named key, so their wording belongs to the locale while every other glyph
/// in the column does not. Resolved here rather than stored in [`SECTIONS`],
/// which stays `const`.
fn glyph_for(lang: Lang, key: &'static str, description: &Msg) -> String {
    match description {
        Msg::HelpFilter => lang.render(&Msg::HelpTypeGlyph),
        Msg::HelpAutoRevert => lang.render(&Msg::HelpWaitGlyph),
        _ => key.to_owned(),
    }
}

/// Draws the overlay over the interface.
///
/// `scroll` is how far down the list has been moved, in lines.
pub fn render(frame: &mut Frame, lang: Lang, scroll: u16) {
    let area = layout::centred(WIDTH, HEIGHT, frame.area());

    // Clear first, or the interface underneath shows through.
    frame.render_widget(Clear, area);

    let all = lines(lang);
    let visible_height = area.height.saturating_sub(layout::DIALOG_CHROME_ROWS);
    let max_scroll = (all.len() as u16).saturating_sub(visible_height);
    let scroll = scroll.min(max_scroll);

    // The hint says which keys move the list, but only while there is
    // something below the fold to move to.
    let footer = if max_scroll > 0 {
        lang.render(&Msg::HelpMoreBelow {
            percent: percentage(scroll, max_scroll),
        })
    } else {
        lang.render(&Msg::HelpAnyKeyCloses)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(style::BORDER_FOCUSED)
        .title(Span::styled(
            lang.render(&Msg::HelpTitle),
            style::PANE_TITLE,
        ))
        .title_bottom(Span::styled(footer, style::BLOCK_SUBTITLE));

    // The gutter and inset every modal keeps, so the overlay reads like the
    // dialogs beside it rather than as a list pushed against its own frame.
    let inner = layout::inset(block.inner(area), layout::DIALOG_GUTTER as u16, 1);

    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(all).scroll((scroll, 0)), inner);
}

/// How far through the list the view has reached.
const fn percentage(scroll: u16, max_scroll: u16) -> u16 {
    if max_scroll == 0 {
        return 100;
    }

    (scroll as u32 * 100 / max_scroll as u32) as u16
}

/// How far the list can be scrolled inside a given frame.
///
/// The caller clamps its own offset with this, so pressing down at the bottom
/// does nothing rather than scrolling into blank space.
pub fn max_scroll(area: Rect, lang: Lang) -> u16 {
    let height = layout::centred(WIDTH, HEIGHT, area)
        .height
        .saturating_sub(layout::DIALOG_CHROME_ROWS);

    (lines(lang).len() as u16).saturating_sub(height)
}

/// The overlay's full contents.
///
/// Every section is built whether or not it fits: the list scrolls rather than
/// dropping what will not fit, because the sections most worth reading — the
/// keys that cannot be guessed from anywhere else — are the ones at the end.
fn lines(lang: Lang) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    for section in SECTIONS {
        lines.push(Line::styled(lang.render(&section.title), style::HEADING));

        for (key, description) in section.keys {
            let glyph = glyph_for(lang, key, description);

            lines.push(Line::from(vec![
                Span::styled(format!("  {glyph:<12}"), style::KEYBAR_KEY),
                Span::styled(lang.render(description), style::NORMAL),
            ]));
        }

        lines.push(Line::raw(""));
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_with_no_key_glyph_gets_one_from_the_catalogue() {
        // Two rows describe doing something rather than pressing a named key,
        // so their glyph column is a word and belongs to the locale. They carry
        // an empty key in `SECTIONS` and `glyph_for` supplies the word — a
        // pairing nothing but this test enforces. A third such row added
        // without its arm would render an empty column, which reads as a
        // binding with no key rather than as a mistake.
        for section in SECTIONS {
            for (key, description) in section.keys {
                if !key.is_empty() {
                    continue;
                }

                assert!(
                    !glyph_for(Lang::En, key, description).is_empty(),
                    "an entry with no key glyph needs an arm in glyph_for: {description:?}"
                );
            }
        }
    }

    #[test]
    fn every_section_states_at_least_one_key() {
        for section in SECTIONS {
            let title = Lang::En.render(&section.title);

            assert!(!section.keys.is_empty(), "section {title} lists nothing");
            assert!(!title.is_empty());
        }
    }

    #[test]
    fn the_dangerous_keys_are_documented_in_their_own_section() {
        // K and R are the two keys whose meaning cannot be guessed from the
        // rest of the interface, so they must be findable here.
        let verify = SECTIONS
            .iter()
            .find(|section| Lang::En.render(&section.title).contains("lock you out"))
            .expect("the verification keys must have a section");

        let keys: Vec<&str> = verify.keys.iter().map(|(key, _)| *key).collect();

        assert!(keys.contains(&"K"), "got {keys:?}");
        assert!(keys.contains(&"R"), "got {keys:?}");
    }

    #[test]
    fn every_section_is_built_whether_or_not_it_fits() {
        // The sections most worth reading are the ones at the end, so the list
        // scrolls rather than dropping what will not fit.
        let all = lines(Lang::En);

        for section in SECTIONS {
            let title = Lang::En.render(&section.title);

            assert!(
                all.iter().any(|line| line.to_string() == title),
                "section {title} must be present"
            );
        }
    }

    #[test]
    fn the_list_scrolls_when_it_is_taller_than_its_frame() {
        // At the reference size the overlay does not fit, which is exactly the
        // case that used to lose the verification keys.
        assert!(
            max_scroll(Rect::new(0, 0, 80, 24), Lang::En) > 0,
            "the reference size must offer scrolling"
        );
    }

    #[test]
    fn the_overlay_never_grows_past_its_own_height() {
        // It is an overlay, not a screen: on a large terminal it stays the
        // same size and scrolls, rather than covering everything.
        let huge = layout::centred(WIDTH, HEIGHT, Rect::new(0, 0, 200, 200));

        assert_eq!(huge.height, HEIGHT);
        assert_eq!(huge.width, WIDTH);
        assert!(
            max_scroll(Rect::new(0, 0, 200, 200), Lang::En) > 0,
            "the list is longer than the overlay at any terminal size"
        );
    }

    #[test]
    fn the_overlay_fits_the_smallest_usable_terminal() {
        // It is clamped rather than allowed to overflow into nothing.
        let area = layout::centred(WIDTH, HEIGHT, Rect::new(0, 0, 60, 15));

        assert!(area.width <= 60);
        assert!(area.height <= 15);
        assert!(!lines(Lang::En).is_empty(), "something must still be shown");
    }

    #[test]
    fn progress_reads_as_a_percentage_of_the_way_down() {
        assert_eq!(percentage(0, 20), 0);
        assert_eq!(percentage(10, 20), 50);
        assert_eq!(percentage(20, 20), 100);
        assert_eq!(percentage(0, 0), 100, "a list that fits is fully shown");
    }
}
