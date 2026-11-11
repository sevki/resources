//! Classification of process rows for Process Explorer-style highlighting.

use std::time::Duration;

/// UIDs below this are conventionally reserved for the system.
const FIRST_REGULAR_UID: u32 = 1000;
/// `nobody` on most distributions.
const NOBODY_UID: u32 = 65534;

/// The highlighting a process row receives. Variants are ordered by priority,
/// i.e. the first matching one wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowState {
    None,
    /// Process has just ended and is only kept around to be highlighted.
    Ended,
    /// Process has just started.
    New,
    /// Process is stopped (SIGSTOP / job control / ptrace stop).
    Stopped,
    /// Process runs inside a container (Flatpak, Snap, …).
    Sandboxed,
    /// Process belongs to the user running Resources.
    Own,
    /// Process belongs to the system (root, daemon users, …).
    Service,
}

impl RowState {
    /// CSS class applied to the row, `None` if the row isn't highlighted.
    pub fn css_class(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Ended => Some("proc-ended"),
            Self::New => Some("proc-new"),
            Self::Stopped => Some("proc-stopped"),
            Self::Sandboxed => Some("proc-sandboxed"),
            Self::Own => Some("proc-own"),
            Self::Service => Some("proc-service"),
        }
    }

    /// Name used for the `row-state` property of process entries.
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Ended => "ended",
            Self::New => "new",
            Self::Stopped => "stopped",
            Self::Sandboxed => "sandboxed",
            Self::Own => "own",
            Self::Service => "service",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "none" => Self::None,
            "ended" => Self::Ended,
            "new" => Self::New,
            "stopped" => Self::Stopped,
            "sandboxed" => Self::Sandboxed,
            "own" => Self::Own,
            "service" => Self::Service,
            _ => return Option::None,
        })
    }

    pub const ALL_CLASSES: [&'static str; 6] = [
        "proc-ended",
        "proc-new",
        "proc-stopped",
        "proc-sandboxed",
        "proc-own",
        "proc-service",
    ];
}

pub struct RowInfo {
    pub uid: u32,
    pub own_uid: u32,
    /// `/proc/<pid>/stat` state character
    pub state: char,
    pub sandboxed: bool,
    /// `Some(t)` if the process ended `t` ago
    pub ended_for: Option<Duration>,
    /// `Some(t)` if the process was first seen `t` ago, `None` if it was
    /// already there when the list was first populated
    pub seen_for: Option<Duration>,
}

pub fn classify(info: &RowInfo, highlight: Duration) -> RowState {
    if info.ended_for.is_some() {
        return RowState::Ended;
    }
    if info.seen_for.is_some_and(|age| age < highlight) {
        return RowState::New;
    }
    if matches!(info.state, 'T' | 't') {
        return RowState::Stopped;
    }
    if info.sandboxed {
        return RowState::Sandboxed;
    }
    if info.uid == info.own_uid {
        return RowState::Own;
    }
    if info.uid < FIRST_REGULAR_UID || info.uid == NOBODY_UID {
        return RowState::Service;
    }
    RowState::None
}

#[cfg(test)]
mod tests {
    use super::*;

    const HL: Duration = Duration::from_secs(2);

    fn info() -> RowInfo {
        RowInfo {
            uid: 1000,
            own_uid: 1000,
            state: 'S',
            sandboxed: false,
            ended_for: None,
            seen_for: None,
        }
    }

    #[test]
    fn names_roundtrip() {
        for state in [
            RowState::None,
            RowState::Ended,
            RowState::New,
            RowState::Stopped,
            RowState::Sandboxed,
            RowState::Own,
            RowState::Service,
        ] {
            assert_eq!(RowState::from_name(state.name()), Some(state));
        }
        assert_eq!(RowState::from_name("bogus"), Option::None);
    }

    #[test]
    fn own_and_service() {
        assert_eq!(classify(&info(), HL), RowState::Own);
        assert_eq!(
            classify(&RowInfo { uid: 0, ..info() }, HL),
            RowState::Service
        );
        assert_eq!(
            classify(
                &RowInfo {
                    uid: 65534,
                    ..info()
                },
                HL
            ),
            RowState::Service
        );
        assert_eq!(
            classify(
                &RowInfo {
                    uid: 1234,
                    ..info()
                },
                HL
            ),
            RowState::None
        );
    }

    #[test]
    fn root_running_resources_is_own_not_service() {
        assert_eq!(
            classify(
                &RowInfo {
                    uid: 0,
                    own_uid: 0,
                    ..info()
                },
                HL
            ),
            RowState::Own
        );
    }

    #[test]
    fn new_expires_after_highlight_duration() {
        let fresh = RowInfo {
            seen_for: Some(Duration::from_secs(1)),
            ..info()
        };
        let old = RowInfo {
            seen_for: Some(Duration::from_secs(2)),
            ..info()
        };
        assert_eq!(classify(&fresh, HL), RowState::New);
        assert_eq!(classify(&old, HL), RowState::Own);
    }

    #[test]
    fn zero_duration_never_highlights_new() {
        let fresh = RowInfo {
            seen_for: Some(Duration::ZERO),
            ..info()
        };
        assert_eq!(classify(&fresh, Duration::ZERO), RowState::Own);
    }

    #[test]
    fn priorities() {
        let all = RowInfo {
            state: 'T',
            sandboxed: true,
            seen_for: Some(Duration::ZERO),
            ended_for: Some(Duration::ZERO),
            ..info()
        };
        assert_eq!(classify(&all, HL), RowState::Ended);
        assert_eq!(
            classify(
                &RowInfo {
                    ended_for: None,
                    ..all
                },
                HL
            ),
            RowState::New
        );
    }

    #[test]
    fn stopped_beats_sandboxed() {
        assert_eq!(
            classify(
                &RowInfo {
                    state: 't',
                    sandboxed: true,
                    ..info()
                },
                HL
            ),
            RowState::Stopped
        );
        assert_eq!(
            classify(
                &RowInfo {
                    sandboxed: true,
                    ..info()
                },
                HL
            ),
            RowState::Sandboxed
        );
    }
}
