use std::{
    collections::HashMap,
    str::from_utf8,
    sync::{Arc, Mutex},
    thread::{self},
};

use crate::tel::TEL;
use base64::URL_SAFE;
use jolocom_native_utils::did_document::{state_to_did_document, DIDDocument};
use keri::{
    derivation::self_addressing::SelfAddressing,
    event::sections::seal::EventSeal,
    prefix::{IdentifierPrefix, Prefix},
    state::IdentifierState,
};

use crate::{
    entity::Entity,
    error::Error,
    tcp_communication::TCPCommunication,
    tel::{
        tel_event::{Operation, TelEvent},
        tel_manager::TelManager,
    },
};

pub enum SignatureState {
    Ok,
    Wrong,
    Revoked,
}

#[derive(Clone)]
pub struct SharedController {
    controller: Arc<Mutex<Controller>>,
}

impl SharedController {
    pub fn new(db_path: &str, address: &str, address_store_path: &str) -> Result<Self, Error> {
        Ok(Self {
            controller: Arc::new(Mutex::new(Controller::new(
                db_path,
                address,
                address_store_path,
            ))),
        })
    }

    pub fn from_controller(controller: Controller) -> Result<Self, Error> {
        Ok(Self {
            controller: Arc::new(Mutex::new(controller)),
        })
    }

    // pub fn new_from_seeds(
    //     db_path: &str,
    //     address: &str,
    //     seeds: &str,
    //     address_store_path: &str,
    // ) -> Result<Self, Error> {
    //     Ok(Self {
    //         ent: Arc::new(Mutex::new(
    //             Entity::new_from_seeds(db_path, address, seeds, address_store_path).unwrap(),
    //         )),
    //     })
    // }

    pub fn get_did_doc(&self, id: &str) -> Result<String, Error> {
        let e = self.controller.lock().unwrap();
        Ok(serde_json::to_string_pretty(&e.get_did_doc(id, &e.main_entity)?).unwrap())
    }

    pub fn update_keys(&mut self) -> Result<(), Error> {
        let mut e = self.controller.lock().unwrap();
        e.update_keys()
    }

    pub fn append(&mut self, msg: &str) -> Result<(), Error> {
        let mut e = self.controller.lock().unwrap();
        e.main_entity.append(msg)
    }

    pub fn get_prefix(&self) -> Result<String, Error> {
        let e = self.controller.lock().unwrap();
        e.main_entity.get_prefix()
    }

    pub fn add_identifier(&mut self, db_path: &str) -> Result<(), Error> {
        let mut e = self.controller.lock().unwrap();
        e.add_entity(db_path)
    }

    pub fn remove_identifier(&mut self, id: &str) -> Result<(), Error> {
        let mut e = self.controller.lock().unwrap();
        e.remove_entity(id)
    }

    pub fn current_identifiers(&self) -> Result<Vec<String>, Error> {
        let e = self.controller.lock().unwrap();
        Ok(e.entities.keys().cloned().collect())
    }

    pub fn run(self) -> Result<(), Error> {
        Controller::run(self.controller)
    }

    pub fn sign_by(&self, id: &str, msg: &str) -> Result<Vec<u8>, Error> {
        let e = self.controller.lock().unwrap();
        e.sign_by(id, msg)
    }

    pub fn sign(&self, msg: &str) -> Result<Vec<u8>, Error> {
        let e = self.controller.lock().unwrap();
        e.sign(msg)
    }

    pub fn verify(&self, issuer_id: &str, msg: &str, signature: &str) -> Result<bool, Error> {
        let e = self.controller.lock().unwrap();
        e.verify(issuer_id, msg, signature)
    }

    pub fn get_kerl(&self) -> Result<String, Error> {
        let e = self.controller.lock().unwrap();
        Ok(TCPCommunication::format_event_stream(
            &e.main_entity.get_kerl()?,
            false,
        ))
    }

    pub fn get_formatted_kerl(&self) -> Result<String, Error> {
        let e = self.controller.lock().unwrap();
        let kerl = &e.main_entity.get_kerl()?;
        Ok(TCPCommunication::format_event_stream(kerl, false))
    }
    
    pub fn get_formatted_tel(&self, vc_dig: &str) -> Result<String, Error> {
        let e = self.controller.lock().unwrap();
        let vc_dig_vec = base64::decode_config(vc_dig, URL_SAFE)?;
        let tel = e.tels.get_tel(&vc_dig_vec)?;
        Ok(tel.to_string())
    }

    pub fn verify_vc(&self, issuer_id: &str, vc: &str, signature: &[u8]) -> Result<SignatureState, Error> {
        let e = self.controller.lock().unwrap();
        e.verify_vc(issuer_id, vc.to_string(), signature)
    }

    pub fn issue_vc(&self, vc: &str) -> Result<Vec<u8>, Error> {
        let mut e = self.controller.lock().unwrap();
        e.issue_vc(vc)
    }

    pub fn revoke_vc(&self, vc: &str) -> Result<(), Error> {
        let mut e = self.controller.lock().unwrap();
        e.revoke_vc(vc)
    }
}

pub struct Controller {
    main_entity: Entity,
    comm: TCPCommunication,
    entities: HashMap<String, Entity>,
    tels: TelManager,
}

impl Controller {
    pub fn new(db_path: &str, adr: &str, adr_store_path: &str) -> Self {
        let comm = TCPCommunication::new(adr, adr_store_path);
        match &comm {
            Ok(_) => {}
            Err(e) => {
                println!("\n{:?}\n", e);
            }
        }
        let comm = comm.unwrap();
        let ent = Entity::new(db_path).unwrap();
        let pref = &ent.get_prefix().unwrap();
        let entities = HashMap::new();
        comm.register(pref).unwrap();
        Controller {
            main_entity: ent,
            comm,
            entities,
            tels: TelManager::new(),
        }
    }

    pub fn add_entity(&mut self, db_path: &str) -> Result<(), Error> {
        let ent = Entity::new(db_path)?;
        let id = ent.get_prefix()?;
        self.comm.register(&id)?;
        match self.entities.insert(id, ent) {
            Some(_) => Err(Error::Generic("Entity already exist".into())),
            None => Ok(()),
        }
    }

    pub fn remove_entity(&mut self, id: &str) -> Result<(), Error> {
        match self.entities.remove(id.into()) {
            Some(_) => Ok(()),
            None => Err(Error::Generic("No such entity".into())),
        }
    }

    pub fn sign_by(&self, id: &str, msg: &str) -> Result<Vec<u8>, Error> {
        let ent = self.entities.get(id).unwrap();
        ent.sign(msg)
    }

    pub fn sign(&self, msg: &str) -> Result<Vec<u8>, Error> {
        self.main_entity.sign(msg)
    }

    pub fn verify(&self, issuer_id: &str, msg: &str, signature: &str) -> Result<bool, Error> {
        let ddoc = self.get_did_doc(issuer_id, &self.main_entity)?;

        self.main_entity.verify(&ddoc, msg, signature)
    }

    pub fn update_keys(&mut self) -> Result<(), Error> {
        self.main_entity.update_keys()
    }

    pub fn append(&mut self, msg: &str) -> Result<(), Error> {
        self.main_entity.append(msg)
    }

    pub fn get_kerl(&self) -> Result<Vec<u8>, Error> {
        self.main_entity.get_kerl()
    }

    pub fn get_did_doc(&self, id: &str, ent: &Entity) -> Result<DIDDocument, Error> {
        let pref: IdentifierPrefix = id.parse().map_err(|e| Error::KeriError(e))?;
        let state = self
            .get_state(&pref, ent)?
            .ok_or(Error::Generic(format!("There is no state for {}.", id)))?;
        Ok(state_to_did_document(state, "keri"))
    }

    fn make_tel_event(&mut self, vc: &str, operation: Operation) -> Result<(), Error> {
        // Add interaction event with vc seal to kel
        let vc_digest = blake3::hash(vc.as_bytes()).as_bytes().to_vec();
        self.main_entity.append(vc)?;

        // Create event seal.
        let event_seal = {
            let prefix: IdentifierPrefix = self.main_entity.get_prefix()?.parse()?;
            let state = self.get_state(&prefix, &self.main_entity)?.unwrap();
            let sn = state.sn;
            let last = state.last;
            let event_digest = SelfAddressing::Blake3_256.derive(&last);

            EventSeal {
                prefix,
                sn,
                event_digest,
            }
        };

        // Then create issuance event, with that seal.
        let mut isev = TelEvent::new(event_seal, operation);
        // Sign this event with current keys.
        let msg = serde_json::to_vec(&isev).unwrap();
        let signature = self.sign(from_utf8(&msg).unwrap()).unwrap();
        isev.attach_signature(&signature);

        // Update tels
        self.tels.process_tel_event(&vc_digest, isev)?;

        Ok(())
    }

    pub fn issue_vc(&mut self, vc: &str) -> Result<Vec<u8>, Error> {
        self.make_tel_event(vc, Operation::Issue)?;
        self.sign(vc)
    }

    pub fn revoke_vc(&mut self, vc: &str) -> Result<(), Error> {
        self.make_tel_event(vc, Operation::Revoke)
    }

    pub fn verify_vc(&self, issuer: &str, vc: String, signature: &[u8]) -> Result<SignatureState, Error> {
        // Make sure that issuer kel is in db
        {
            self.get_state(&issuer.parse::<IdentifierPrefix>()?, &self.main_entity)?;
        }
        // Ask issuer for tel
        let address = self.comm.get_address_for_prefix(issuer)?.unwrap();
        let tel: TEL = {
            let tel_vec = TCPCommunication::ask_for_tel(vc.as_bytes(), &address)?;
            serde_json::from_str(from_utf8(&tel_vec).unwrap().trim()).unwrap()
        };
        let vc_dig = base64::encode_config(&blake3::hash(vc.as_bytes()).as_bytes().to_vec(), URL_SAFE);
        println!("TEL for VC of digest {}:\n{}\n", vc_dig, tel.to_string());

        self.main_entity.verify_vc(vc.as_bytes(), signature, &tel)
    }

    pub fn run(controller: Arc<Mutex<Controller>>) -> Result<(), Error> {
        let address = {
            let cont = controller.lock().unwrap();
            cont.comm.get_address()
        };
        thread::spawn(move || {
            TCPCommunication::run(address, controller).expect("server runing failure");
        });
        Ok(())
    }

    pub fn parse_message(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let msg_str = from_utf8(message).map_err(|e| Error::Generic(e.to_string()))?;
        let mut splitter = msg_str.splitn(2, ' ');
        let command = splitter
            .next()
            .ok_or(Error::Generic("Improper message format".into()))?;
        let arg = splitter
            .next()
            .ok_or(Error::Generic("Improper message format".into()))?;

        match command {
            "tel" => {
                let vc_dig = blake3::hash(arg.as_bytes()).as_bytes().to_vec();
                // let vc_dig_b64 = base64::encode(vc_dig).as_bytes().to_vec();
                let tel = self.tels.get_tel(&vc_dig)?;
                serde_json::to_vec(tel).map_err(|e| Error::Generic(e.to_string()))
            }
            _ => {
                println!(
                    "{}",
                    TCPCommunication::format_event_stream(arg.as_bytes(), true)
                );
                let ent = if command == self.main_entity.get_prefix().unwrap() {
                    &self.main_entity
                } else {
                    self.entities.get(command).unwrap()
                };
                ent.respond(arg.as_bytes())
            }
        }
    }

    pub fn get_state(
        &self,
        id: &IdentifierPrefix,
        entity: &Entity,
    ) -> Result<Option<IdentifierState>, Error> {
        match entity.get_state_for_prefix(id)? {
            Some(state) => Ok(Some(state)),
            None => {
                let kerl = entity.get_kerl()?;
                let addr =
                    self.comm
                        .get_address_for_prefix(&id.to_str())?
                        .ok_or(Error::Generic(format!(
                            "Can't find address for prefix {}",
                            id.to_str()
                        )))?;
                TCPCommunication::send(&kerl, &addr, &id.to_str(), entity)?;

                Ok(entity.get_state_for_prefix(id)?)
            }
        }
    }

    // pub fn get_kerl_for_pref(&self, prefix: &str) -> Result<Vec<u8>, Error> {
    //     self.main_entity.get_state_for_prefix(id)
    //      let kerl = self
    //         .keri
    //         .get_kerl()
    //         .map_err(|e| Error::KeriError(e))?
    //         .unwrap_or(vec![])
    //     Ok(())
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vc() -> Result<(), Error> {
        use crate::tel::tel_event::TelState;
        use tempfile::tempdir;
        let db_dir = tempdir()?;
        let db_path = db_dir.path().to_str().unwrap();
        let adr_store_path = [db_dir.path().to_str().unwrap(), "adr"].join("");

        let mut cont = Controller::new(db_path, "localhost:1212", &adr_store_path);

        // Compute vc related stuff
        let vc = "Some vc";
        let vc_digest = blake3::hash(vc.as_bytes()).as_bytes().to_vec();
        let vc_signature = cont.sign(vc)?;

        cont.issue_vc(vc)?;

        let vc_state = cont.tels.get_state(&vc_digest)?;
        assert!(matches!(vc_state, TelState::Issued(_)));

        let ver = {
            let tel = cont.tels.get_tel(&vc_digest)?;
            cont.main_entity
                .verify_vc(vc.as_bytes(), &vc_signature, tel)?
        };
        assert!(matches!(ver, SignatureState::Ok));

        // Rotate keys and verify vc again.
        cont.update_keys()?;
        let ver = {
            let tel = cont.tels.get_tel(&vc_digest)?;
            cont.main_entity
                .verify_vc(vc.as_bytes(), &vc_signature, tel)?
        };
        assert!(matches!(ver, SignatureState::Ok));

        cont.revoke_vc(vc)?;

        let vc_state = cont.tels.get_state(&vc_digest)?;
        assert!(matches!(vc_state, TelState::Revoked));

        let tel = cont.tels.get_tel(&vc_digest)?;
        let ver = cont
            .main_entity
            .verify_vc(vc.as_bytes(), &vc_signature, tel)?;
        assert!(matches!(ver, SignatureState::Revoked));

        Ok(())
    }

    #[test]
    pub fn test_communication() -> Result<(), Error> {
        use tempfile::tempdir;
        let db_dir = tempdir()?;
        let db_path = db_dir.path().to_str().unwrap();
        let adr_store_path = [db_dir.path().to_str().unwrap(), "adr"].join("");

        let mut cont = Controller::new(db_path, "localhost:1212", &adr_store_path);
        let prefix = cont.main_entity.get_prefix()?;
        // Compute vc related stuff
        let vc = "Some vc";
        let _vc_digest = blake3::hash(vc.as_bytes()).as_bytes().to_vec();
        let vc_signature = cont.sign(vc)?;

        cont.issue_vc(vc)?;
        cont.update_keys()?;

        let issuer_state = cont.main_entity.get_state_for_prefix(&prefix.parse()?)?;

        let db_dir = tempdir()?;
        let db_path = db_dir.path().to_str().unwrap();
        let issuer = SharedController::from_controller(cont)?;
        issuer.clone().run()?;

        let shared_asker = SharedController::new(db_path, "localhost:3232", &adr_store_path)?;
        shared_asker.clone().run()?;

        let ver = shared_asker.verify_vc(&prefix, vc, &vc_signature)?;

        let issuer_state_in_asker = shared_asker
            .controller
            .lock()
            .unwrap()
            .main_entity
            .get_state_for_prefix(&prefix.parse()?)?;
        assert_eq!(issuer_state.unwrap().sn, issuer_state_in_asker.unwrap().sn);

        assert!(matches!(ver, SignatureState::Ok));

        issuer.revoke_vc(vc)?;
        let ver = shared_asker.verify_vc(&prefix, vc, &vc_signature)?;
        assert!(matches!(ver, SignatureState::Revoked));

        Ok(())
    }
}
