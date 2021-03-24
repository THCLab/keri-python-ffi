use std::convert::TryInto;

use crate::error::Error;
use keri::{
    event::sections::{seal::EventSeal, KeyConfig},
    event_message::parse,
    prefix::Prefix,
    state::{EventSemantics, IdentifierState},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
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

    #[serde(skip_serializing)]
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

    /// Returns current Key Config associated with given event seal.
    /// Note: Similar to function `get_keys_at_sn` in processor module in keriox,
    /// but without processor.
    fn get_keys_at_sn(&self, seal: &EventSeal, kel: &[u8]) -> Result<KeyConfig, Error> {
        let sn = seal.sn;
        let pref = seal.prefix.clone();
        let s = parse::signed_event_stream(&kel).unwrap().1;

        let state = s
            .into_iter()
            .take_while(|ev| match ev {
                parse::Deserialized::Event(e) => {
                    // println!("sn: {}", e.event.event.event.sn);
                    e.event.event.event.prefix == pref && e.event.event.event.sn <= sn
                }
                parse::Deserialized::Vrc(_) => true,
                parse::Deserialized::Rct(_) => true,
            })
            .fold(IdentifierState::default(), |st, e| {
                let em = match e {
                    parse::Deserialized::Event(e) => e.event.event.apply_to(st).unwrap(),
                    parse::Deserialized::Vrc(_) => st,
                    parse::Deserialized::Rct(_) => st,
                };
                em
            });

        // Check if seal digest and digest of last state event match.
        if seal.event_digest.derivation.derive(&state.last) != seal.event_digest {
            Err(Error::Generic(
                "seal digest doesnt match last event's digest".into(),
            ))
        } else {
            Ok(state.current)
        }
    }

    pub fn verify(&self, kel: &[u8]) -> Result<bool, Error> {
        let keys = self.get_keys_at_sn(&self.event_seal, kel)?;

        let bp = keys.public_keys.get(0).unwrap();
        let key_type = bp.derivation_code();
        let public_key = bp.derivative();
        let verification = match key_type.as_str() {
            "D" => {
                // With dalek.
                use ed25519_dalek::{PublicKey, Signature, Verifier};
                let pk = PublicKey::from_bytes(&public_key).unwrap();
                let array_signature: [u8; 64] = self.signature.clone().try_into().unwrap();
                let signature = Signature::new(array_signature);
                let msg = &serde_json::to_vec(&self).unwrap();
                pk.verify(msg, &signature).is_ok()

                // With ursa.
                // let pub_key = PublicKey {0: public_key.to_vec()};
                // let ed = ursa::signatures::ed25519::Ed25519Sha512::new();
                // let msg = &serde_json::to_vec(&self).unwrap();
                // ed.verify(msg, &self.signature, &pub_key).map_err(|e| Error::Generic(e.to_string()))?
            }
            _ => false,
        };
        Ok(verification)
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
