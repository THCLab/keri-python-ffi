use crate::error::Error;
use keri::event::sections::seal::EventSeal;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TelState {
    NotIsuued,
    Issued(EventSeal),
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    Issue,
    Revoke,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelEvent {
    event_seal: EventSeal,
    operation: Operation,

    // #[serde(skip_serializing)]
    signature: Vec<u8>,
}

impl TelEvent {
    pub fn new(event_seal: EventSeal, operation: Operation) -> Self {
        TelEvent {
            event_seal,
            operation,
            signature: vec![],
        }
    }

    pub fn apply(&self, prev_state: &TelState) -> Result<TelState, Error> {
        match self.operation {
            Operation::Issue => match prev_state {
                TelState::NotIsuued => Ok(TelState::Issued(self.event_seal.clone())),
                _ => Err(Error::Generic("Wrong state".into())),
            },
            Operation::Revoke => match prev_state {
                TelState::Issued(_) => Ok(TelState::Revoked),
                _ => Err(Error::Generic("Wrong state".into())),
            },
        }
    }

    pub fn attach_signature(&mut self, signature: &[u8]) {
        self.signature = signature.to_vec();
    }
}
