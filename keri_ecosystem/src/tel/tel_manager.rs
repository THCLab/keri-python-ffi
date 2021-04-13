use std::collections::HashMap;

use crate::error::Error;

use super::{
    tel_event::{TelEvent, TelState},
    TEL,
};

#[derive(Debug)]
pub struct TelManager {
    tels: HashMap<Vec<u8>, TEL>,
}

impl TelManager {
    pub fn new() -> Self {
        TelManager {
            tels: HashMap::new(),
        }
    }

    pub fn process_tel_event(&mut self, vc_dig: &[u8], event: TelEvent) -> Result<(), Error> {
        let tel = match self.tels.get_mut(vc_dig) {
            Some(tel) => tel.update(event)?,
            None => TEL::new().update(event)?,
        };
        self.tels.insert(vc_dig.to_vec(), tel);

        Ok(())
    }

    pub fn get_state(&self, vc_dig: &[u8]) -> Result<TelState, Error> {
        let tel = self.tels.get(vc_dig);
        match tel {
            Some(tel) => Ok(tel.get_state()),
            None => Ok(TelState::NotIsuued),
        }
    }

    pub fn get_tel(&self, vc_dig: &[u8]) -> Result<&TEL, Error> {
        self.tels
            .get(vc_dig)
            .ok_or(Error::Generic("No TEl for VC".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::TelManager;
    use crate::error::Error;
    use crate::tel::tel_event::{Operation, TelEvent, TelState};
    use keri::event::sections::seal::EventSeal;

    #[test]
    fn test_process() -> Result<(), Error> {
        let vc = "Some vc";
        let vc_digest = blake3::hash(vc.as_bytes()).as_bytes().to_vec();

        let mut tel_manager = TelManager::new();

        let seal_str = r#"{"i":"DhaJFfaW1aoKXZospMvka-VdQlmj0BQd4HlL3JvCOUg8","s":"1","d":"EJbYpX41mdwfdTOY3w65kjwx_E1bzqhaNFZLDRSEBaVk"}"#;
        let issuing_event_seal = serde_json::from_str(seal_str).unwrap();

        let iss_event = TelEvent::new(issuing_event_seal, Operation::Issue);

        tel_manager.process_tel_event(&vc_digest, iss_event)?;

        let vc_state = tel_manager.get_state(&vc_digest)?;
        assert!(matches!(vc_state, TelState::Issued(_)));

        let rev_seal_str = r#"{"i":"DhaJFfaW1aoKXZospMvka-VdQlmj0BQd4HlL3JvCOUg8","s":"3","d":"EChnM_a1gMogM8utFBk0Fdlj-P8Sx963VR7mCPYTbVXs"}"#;
        let revoking_event_seal: EventSeal = serde_json::from_str(rev_seal_str).unwrap();

        let rev_event = TelEvent::new(revoking_event_seal, Operation::Revoke);

        tel_manager.process_tel_event(&vc_digest, rev_event)?;

        let vc_state = tel_manager.get_state(&vc_digest)?;
        assert!(matches!(vc_state, TelState::Revoked));

        // Try to revoke not issued vc.
        let not_issued_vc = "not issued vc";
        let not_issued_vc_digest = blake3::hash(not_issued_vc.as_bytes()).as_bytes().to_vec();

        let rev_seal = r#"{"i":"DIhUJMEYCsLSWhZ1TtvXI2Z9WZmWOBrtozLrLJwmNexI","s":"3","d":"EWhbaXRxADbR0yOmLqRRW2XzEKR0tyE8EbjqlGOaJg-o"}"#;
        let revoking_event_seal: EventSeal = serde_json::from_str(rev_seal).unwrap();

        let rev_event = TelEvent::new(revoking_event_seal, Operation::Revoke);
        assert!(tel_manager
            .process_tel_event(&not_issued_vc_digest, rev_event)
            .is_err());

        let vc_state = tel_manager.get_state(&not_issued_vc_digest)?;
        assert!(matches!(vc_state, TelState::NotIsuued));

        Ok(())
    }
}
