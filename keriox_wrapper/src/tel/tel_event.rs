use std::fmt;

use crate::error::Error;
use base64::URL_SAFE;
use keri::{event::sections::seal::EventSeal, prefix::Prefix};
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


impl fmt::Display for TelEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let issuer = ["issuer: ", &self.event_seal.prefix.to_str()].join("");
        let operation = ["operation: ", &serde_json::to_string(&self.operation).unwrap()].join("");
        let signature = ["signature: ", &base64::encode_config(&self.signature, URL_SAFE)].join("");
        let sn = ["sn: ", &self.event_seal.sn.to_string()].join("");
        let digest = ["issuence event digest: ", &self.event_seal.event_digest.to_str()].join("");

    write!(f, "\t{}", [sn, operation].join(", "))
    }
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
