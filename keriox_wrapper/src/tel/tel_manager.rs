use std::collections::HashMap;

use keri::event::sections::seal::EventSeal;

use crate::error::Error;

use super::{
    tel_event::{Operation, TelEvent, TelState},
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

    pub fn make_issue_event(issuing_event_seal: EventSeal) -> Result<TelEvent, Error> {
        // let dig = blake3::hash(vc);
        let iss_event = TelEvent::new(issuing_event_seal, Operation::Issue);
        Ok(iss_event)
    }

    pub fn make_revoke_event(revoking_event_seal: EventSeal) -> Result<TelEvent, Error> {
        let rev_event = TelEvent::new(revoking_event_seal, Operation::Revoke);
        Ok(rev_event)
    }

    pub fn process_tel_event(
        &mut self,
        vc_dig: &[u8],
        event: TelEvent,
        kel: &[u8],
    ) -> Result<(), Error> {
        let tel = match self.tels.get_mut(vc_dig) {
            Some(tel) => tel.update(event, kel)?,
            None => TEL::new().update(event, kel)?,
        };
        self.tels.insert(vc_dig.to_vec(), tel);

        Ok(())
    }

    pub fn get_state(&self, vc_dig: Vec<u8>) -> Result<TelState, Error> {
        let tel = self
            .tels
            .get(&vc_dig)
            .ok_or(Error::Generic("There's no tel".into()))?;
        let state = tel.get_state();
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::{Operation, TelEvent, TelManager, TelState, TEL};
    use crate::entity::Entity;
    use keri::{
        derivation::self_addressing::SelfAddressing, event::sections::seal::EventSeal,
        event_message::parse,
    };
    use std::str::from_utf8;
    use tempfile::tempdir;

    use crate::error::Error;
    #[test]
    fn test_vc() -> Result<(), Error> {
        let db_dir = tempdir()?;
        let db_path = db_dir.path().to_str().unwrap();

        // Create Entity to have wallet and corresponding kel.
        let mut ent = Entity::new(db_path).unwrap();

        // Compute vc related stuff
        let vc = "Some vc";
        let vc_digest = blake3::hash(vc.as_bytes()).as_bytes().to_vec();
        let vc_signature = ent.sign(vc)?;

        // Add interaction event with vc seal to kel
        ent.append(vc)?;
        let kel = ent.get_kerl().unwrap();

        let mut tel_manager = TelManager::new();

        // Parse interaction event message to create issuing event seal.
        let ixn_event = parse::signed_event_stream(&kel).unwrap().1;
        let ixn = ixn_event.last().unwrap();
        let event = match ixn {
            parse::Deserialized::Event(e) => Ok(e.event.event.clone()),
            _ => Err(Error::Generic("Wrong event type".into())),
        }?;
        let serialized = event.serialize().unwrap();
        let pref = event.event.prefix;
        let sn = event.event.sn;
        let dig = SelfAddressing::Blake3_256.derive(&serialized);
        let issuing_event_seal = EventSeal {
            prefix: pref,
            sn: sn,
            event_digest: dig,
        };

        // Then create issuance event, with that seal.
        let mut isev = TelManager::make_issue_event(issuing_event_seal)?;
        // Sign this event with current keys.
        let msg = serde_json::to_vec(&isev).unwrap();
        let signature = ent.sign(from_utf8(&msg).unwrap()).unwrap();
        isev.attach_signature(&signature);

        tel_manager.process_tel_event(&vc_digest, isev, &kel)?;

        assert!(matches!(
            tel_manager.get_state(vc_digest)?,
            TelState::Issued(_)
        ));

        Ok(())
    }
}
