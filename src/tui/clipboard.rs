//! Putting text on the operator's clipboard, through the terminal itself.
//!
//! The problem this solves is that a mouse cannot select the output pane. The
//! terminal owns the selection and sees one grid of cells, so dragging over
//! the log takes the pane's border and the tree's flags with it — and takes
//! only what the pane is wide enough to show, cutting every line that scrolls.
//! `initd` cannot restrict that: intercepting the mouse would disable the
//! terminal's own selection entirely and replace it with nothing.
//!
//! So the transcript is offered by a key instead, and it carries the whole
//! lines rather than the visible part of them.
//!
//! **OSC 52 rather than a clipboard crate or `xclip`.** This tool administers
//! remote servers: the machine it runs on usually has no display server, no
//! `xclip`, no `wl-copy`, and its clipboard would be the wrong one anyway —
//! the operator is sitting at the other end of an SSH connection. OSC 52 asks
//! the *terminal* to set the clipboard, so the text lands where the operator
//! actually is. It travels through SSH and tmux for the same reason, being
//! nothing but bytes on the same stream the interface already draws with, and
//! adds no dependency to audit.
//!
//! What it cannot do is report success: the sequence is written and the
//! terminal either honours it or ignores it, with no reply. Terminals that
//! ignore it are real — some ship with it disabled, since a program that can
//! write the clipboard can also overwrite what was in it. So the interface
//! says what it *sent*, never that it was received; claiming otherwise would
//! be a message the operator cannot act on when it is wrong.

use std::io::Write as _;

/// Base64 alphabet, per RFC 4648.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Writes `text` to the terminal's clipboard.
///
/// Returns whether the sequence reached the terminal, which is not whether the
/// clipboard was set — see the module docs. A write that fails is reported
/// rather than ignored, because the two failures look identical on screen and
/// only one of them is worth telling the operator about.
pub fn copy(text: &str) -> bool {
    // `c` is the selection to set: the clipboard proper, rather than the
    // primary selection, which is what a middle-click pastes and is not what
    // an operator pressing a copy key means.
    let sequence = format!("\x1b]52;c;{}\x07", encode(text.as_bytes()));

    let mut stdout = std::io::stdout();

    // Flushed here rather than left to the next frame: the interface writes
    // through ratatui's buffer, and a sequence sitting behind a redraw would
    // reach the terminal at a moment unrelated to the keystroke.
    stdout.write_all(sequence.as_bytes()).is_ok() && stdout.flush().is_ok()
}

/// Encodes bytes as base64.
///
/// Hand-rolled rather than depending on a crate: it is the one thing OSC 52
/// needs, it is twenty lines, and every dependency here is one to audit in a
/// tool that runs as root.
fn encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        // Three bytes become four six-bit groups. A short final chunk is
        // padded with zero bits here and with `=` below, which is what
        // distinguishes "the input ended" from "the last group was zero".
        let mut block = 0u32;

        for (index, byte) in chunk.iter().enumerate() {
            block |= u32::from(*byte) << (16 - 8 * index);
        }

        for index in 0..4 {
            if index <= chunk.len() {
                let group = (block >> (18 - 6 * index)) & 0b0011_1111;

                // The index cannot exceed 63, having just been masked to six
                // bits, so this cannot be `None`; `map_or` states that without
                // an `unwrap` on a path that runs as root.
                encoded.push(ALPHABET.get(group as usize).map_or('A', |&b| b as char));
            } else {
                encoded.push('=');
            }
        }
    }

    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_vectors_from_the_rfc() {
        // RFC 4648 section 10, which exists precisely so an implementation can
        // be checked rather than believed. The padding cases are the ones a
        // hand-rolled encoder gets wrong.
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn encodes_a_transcript_line_whole() {
        // The case this feature exists for: a line wider than the pane, which
        // the mouse would have copied truncated.
        let line = "cosmin:x:1000:1000::/home/cosmin:/usr/bin/fish";

        let encoded = encode(line.as_bytes());

        assert_eq!(
            encoded,
            "Y29zbWluOng6MTAwMDoxMDAwOjovaG9tZS9jb3NtaW46L3Vzci9iaW4vZmlzaA=="
        );
    }

    #[test]
    fn encodes_bytes_above_ascii() {
        // A package manager's output carries accented characters and box
        // drawing; encoding bytes rather than chars is what makes that work,
        // and a `char`-based encoder would produce something the terminal
        // decodes to mojibake.
        assert_eq!(encode("é".as_bytes()), "w6k=");
        assert_eq!(encode("─".as_bytes()), "4pSA");
    }

    #[test]
    fn the_length_is_always_a_multiple_of_four() {
        // Padding is what guarantees this, and a decoder that receives an
        // unpadded string is entitled to reject the whole sequence.
        for length in 0..32 {
            let input = vec![b'x'; length];

            assert_eq!(
                encode(&input).len() % 4,
                0,
                "{length} bytes encoded to a length that is not a multiple of four"
            );
        }
    }
}
