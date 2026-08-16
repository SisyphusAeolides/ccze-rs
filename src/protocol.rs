//! Runtime counterpart of the total Idris protocol state machine.

use crate::severity::find_ascii_case_insensitive;
use std::fmt;

/// Valid service lifecycle phases.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(i32)]
pub enum Phase {
    #[default]
    Cold = 0,
    Started = 1,
    Authenticated = 2,
    Bound = 3,
    Ready = 4,
}

/// Lifecycle events recognized in log messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Event {
    Start = 0,
    Authenticate = 1,
    Bind = 2,
    Ready = 3,
    Reset = 4,
}

extern "C" {
    fn ccze_protocol_step(phase: i32, event: i32) -> i32;
}

/// Stateful validator for `Start -> Authenticate -> Bind -> Ready` protocols.
#[derive(Debug, Default)]
pub struct ProtocolVerifier {
    phase: Phase,
}

impl ProtocolVerifier {
    /// Returns the current phase.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// Detects a lifecycle event and validates its transition.
    pub fn inspect(&mut self, line: &[u8]) -> Option<Result<Phase, Violation>> {
        let event = Event::detect(line)?;
        let previous = self.phase;
        // Enum representations are constrained to the inputs accepted by the C ABI.
        let next = unsafe { ccze_protocol_step(previous as i32, event as i32) };
        let Some(next) = Phase::from_code(next) else {
            return Some(Err(Violation { previous, event }));
        };
        self.phase = next;
        Some(Ok(next))
    }
}

impl Event {
    fn detect(line: &[u8]) -> Option<Self> {
        [
            (b"authenticate".as_slice(), Self::Authenticate),
            (b"authenticated".as_slice(), Self::Authenticate),
            (b"ready".as_slice(), Self::Ready),
            (b"reset".as_slice(), Self::Reset),
            (b"start".as_slice(), Self::Start),
            (b"bind".as_slice(), Self::Bind),
        ]
        .into_iter()
        .find_map(|(word, event)| find_ascii_case_insensitive(line, word).map(|_| event))
    }
}

impl Phase {
    const fn from_code(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Cold),
            1 => Some(Self::Started),
            2 => Some(Self::Authenticated),
            3 => Some(Self::Bound),
            4 => Some(Self::Ready),
            _ => None,
        }
    }
}

/// An event that is impossible from the current phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Violation {
    pub previous: Phase,
    pub event: Event,
}

impl fmt::Display for Violation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid {:?} event while in {:?} phase",
            self.event, self.previous
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_proven_sequence() {
        let mut verifier = ProtocolVerifier::default();
        for line in [
            "service start",
            "authenticate user",
            "bind socket",
            "server ready",
        ] {
            assert!(matches!(verifier.inspect(line.as_bytes()), Some(Ok(_))));
        }
        assert_eq!(verifier.phase(), Phase::Ready);
    }

    #[test]
    fn rejects_out_of_order_events_without_advancing() {
        let mut verifier = ProtocolVerifier::default();
        assert!(matches!(verifier.inspect(b"server ready"), Some(Err(_))));
        assert_eq!(verifier.phase(), Phase::Cold);
    }

    #[test]
    fn native_table_matches_the_total_idris_definition() {
        let phases = [
            Phase::Cold,
            Phase::Started,
            Phase::Authenticated,
            Phase::Bound,
            Phase::Ready,
        ];
        let events = [
            Event::Start,
            Event::Authenticate,
            Event::Bind,
            Event::Ready,
            Event::Reset,
        ];
        for phase in phases {
            for event in events {
                let expected = if event == Event::Reset {
                    Some(Phase::Cold)
                } else if event as i32 == phase as i32 && phase != Phase::Ready {
                    Phase::from_code(phase as i32 + 1)
                } else {
                    None
                };
                // The exhaustive input matrix is made exclusively from valid enum values.
                let actual = unsafe { ccze_protocol_step(phase as i32, event as i32) };
                assert_eq!(Phase::from_code(actual), expected, "{phase:?} + {event:?}");
            }
        }
    }
}
