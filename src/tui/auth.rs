//! Handing the terminal to a privilege helper that needs to prompt.
//!
//! The executor asks before a helper prompts rather than after, because a
//! prompt raised under the interface is written into the alternate screen in
//! raw mode — unreadable and unanswerable, so the interface appears to hang.
//! What lives here is the interface's half of that arrangement: it holds the
//! request, and whoever drains the channel must answer it.
//!
//! The one group of `App`'s behaviour that is genuinely self-contained: it
//! reads three of the struct's twenty-one fields, and `pending_auth` is its
//! own.

use super::Tui;
use super::app::App;
use crate::error::Result;
use crate::exec::{OutputLine, Stream};
use crate::i18n::Msg;

/// A privilege helper waiting to be given the terminal.
pub(super) struct AuthRequest {
    pub(super) program: String,
    pub(super) args: Vec<String>,
    pub(super) mechanism: String,
    pub(super) reply: std::sync::mpsc::Sender<bool>,
}

impl App {
    /// Records a request for the terminal, answering any it displaces.
    ///
    /// A second request while one is outstanding would strand the thread
    /// waiting on the first, so the displaced one is refused rather than
    /// dropped. One task authenticates once at a time in practice; this keeps
    /// that something the code states rather than something it relies on.
    pub(super) fn supersede_pending_auth(&mut self, request: AuthRequest) {
        if let Some(superseded) = self.pending_auth.replace(request) {
            let _ = superseded.reply.send(false);
        }
    }
    /// Hands the terminal to a helper that needs to prompt, and answers.
    ///
    /// The reply is sent on every path, including the one where restoring the
    /// terminal fails: a worker thread is blocked on the other end, and
    /// letting it wait for the deadline instead of telling it no would stall a
    /// task for five minutes over an error already in hand.
    ///
    /// A send failure is ignored, as elsewhere: it means the thread is gone,
    /// which is not this loop's problem to solve.
    pub(super) fn serve_pending_auth(&mut self, terminal: &mut Tui) -> Result<()> {
        let Some(request) = self.pending_auth.take() else {
            return Ok(());
        };

        let outcome = super::with_terminal_released(terminal, || {
            // Every stream inherited: the helper has to reach the terminal to
            // prompt, and on sudo the timestamp it writes is keyed by it.
            let status = std::process::Command::new(&request.program)
                .args(&request.args)
                .stdin(std::process::Stdio::inherit())
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .status()
                .map_err(|source| crate::error::Error::CommandIo {
                    command: request.program.clone(),
                    source,
                })?;

            Ok(status.success())
        });

        let granted = match &outcome {
            Ok(granted) => *granted,
            Err(_) => false,
        };

        let _ = request.reply.send(granted);

        if granted {
            self.output.push(OutputLine {
                stream: Stream::Stdout,
                text: self.lang.render(&Msg::AuthenticationGranted),
            });
        } else {
            self.output.push(OutputLine {
                stream: Stream::Stderr,
                text: self.lang.render(&Msg::AuthenticationRefused {
                    mechanism: request.mechanism.clone(),
                }),
            });
        }

        outcome.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distro::Family;
    use crate::tui::fixtures::test_app;

    #[test]
    fn a_superseded_authentication_request_is_refused_rather_than_dropped() {
        // Both requests have a thread blocked on them. Overwriting the first
        // without answering would leave that thread waiting out the deadline.
        let mut app = test_app(Family::Debian);
        let (first, first_answer) = std::sync::mpsc::channel();
        let (second, _second_answer) = std::sync::mpsc::channel();

        app.pending_auth = Some(AuthRequest {
            program: "sudo".to_owned(),
            args: vec!["-v".to_owned()],
            mechanism: "sudo".to_owned(),
            reply: first,
        });

        app.supersede_pending_auth(AuthRequest {
            program: "sudo".to_owned(),
            args: vec!["-v".to_owned()],
            mechanism: "sudo".to_owned(),
            reply: second,
        });

        assert_eq!(
            first_answer.try_recv(),
            Ok(false),
            "the superseded request must be answered, not abandoned"
        );
    }
}
