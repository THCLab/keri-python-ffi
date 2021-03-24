// use ursa::{keys::PublicKey, signatures::SignatureScheme};
mod tel_event;
mod tel_manager;

use self::tel_event::{TelEvent, TelState};
use crate::error::Error;

#[derive(Debug)]
pub struct TEL {
    events: Vec<TelEvent>,
    state: TelState,
}

impl TEL {
    pub fn new() -> Self {
        TEL {
            events: vec![],
            state: TelState::NotIsuued,
        }
    }

    pub fn update(&self, event: TelEvent, kel: &[u8]) -> Result<TEL, Error> {
        if event.verify(kel)? {
            let state = event.apply(&self.state.clone())?;
            let mut events = self.events.clone();
            events.push(event);
            Ok(TEL { state, events })
        } else {
            Err(Error::Generic("Wrong signatures".into()))
        }
    }

    pub fn get_state(&self) -> TelState {
        self.state.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::tel_event::Operation;
    use super::{TelEvent, TelState, TEL};
    use crate::entity::Entity;
    use keri::{
        derivation::self_addressing::SelfAddressing, event::sections::seal::EventSeal,
        event_message::parse,
    };
    use std::str::from_utf8;
    use tempfile::tempdir;

    use crate::error::Error;
    #[test]
    fn test_issuance() -> Result<(), Error> {
        use crate::entity::Entity;

        let db_dir = tempdir()?;
        let db_path = db_dir.path().to_str().unwrap();

        // Create Entity to have wallet and corresponding kel.
        let mut ent = Entity::new(db_path).unwrap();
        let kel = ent.get_kerl().unwrap();

        // Parse inception message to create event seal.
        let event = parse::message(&kel).unwrap().1.event;
        let serialized = event.serialize().unwrap();
        let pref = event.event.prefix;
        let sn = event.event.sn;
        let dig = SelfAddressing::Blake3_256.derive(&serialized);
        let seal = EventSeal {
            prefix: pref,
            sn: sn,
            event_digest: dig,
        };

        // Then create issuance event, with that seal.
        let mut isev = TelEvent::new(seal.clone(), Operation::Issue);

        // Sign this event with current keys.
        let msg = serde_json::to_vec(&isev).unwrap();
        let signature = ent.sign(from_utf8(&msg).unwrap()).unwrap();
        isev.attach_signature(&signature);

        // Rotate keys, this will add new events to kel, so update it.
        ent.update_keys()?;
        let kel = ent.get_kerl().unwrap();

        assert!(isev.verify(&kel)?);

        // Then create issuance event, with the same seal.
        let mut isev = TelEvent::new(seal, Operation::Issue);

        // Sign this event with current keys (after rotation).
        let msg = serde_json::to_vec(&isev).unwrap();
        let signature = ent.sign(from_utf8(&msg).unwrap()).unwrap();
        isev.attach_signature(&signature);

        assert!(!isev.verify(&kel)?);

        Ok(())
    }

    #[test]
    fn test_state_update() -> Result<(), Error> {
        let db_dir = tempdir()?;
        let db_path = db_dir.path().to_str().unwrap();

        // Create Entity to have wallet and corresponding kel.
        let ent = Entity::new(db_path).unwrap();
        let kel = ent.get_kerl().unwrap();

        // Parse inception message to create event seal.
        let event = parse::message(&kel).unwrap().1.event;
        let serialized = event.serialize().unwrap();
        let pref = event.event.prefix;
        let sn = event.event.sn;
        let dig = SelfAddressing::Blake3_256.derive(&serialized);
        let seal = EventSeal {
            prefix: pref,
            sn: sn,
            event_digest: dig,
        };
        let mut tel = TEL::new();
        assert!(matches!(tel.state, TelState::NotIsuued));
        assert_eq!(0, tel.events.len());

        // Then create issuance event, with that seal.
        let mut isev = TelEvent::new(seal.clone(), Operation::Issue);
        // Sign this event with current keys.
        let msg = serde_json::to_vec(&isev).unwrap();
        let signature = ent.sign(from_utf8(&msg).unwrap()).unwrap();
        isev.attach_signature(&signature);

        tel.update(isev, &kel)?;
        assert!(matches!(tel.state, TelState::Issued(_)));
        assert_eq!(1, tel.events.len());

        // Then create revoke event, (with the same seal).
        let mut revev = TelEvent::new(seal.clone(), Operation::Revoke);
        // Sign this event with current keys.
        let msg = serde_json::to_vec(&revev).unwrap();
        let signature = ent.sign(from_utf8(&msg).unwrap()).unwrap();
        revev.attach_signature(&signature);

        tel.update(revev, &kel)?;
        assert!(matches!(tel.state, TelState::Revoked));
        assert_eq!(2, tel.events.len());

        Ok(())
    }
}
