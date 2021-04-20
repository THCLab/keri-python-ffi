use std::{
    collections::HashMap,
    str::from_utf8,
    sync::{Arc, Mutex},
    thread::{self},
};

use crate::{
    datum::{AttestationDatum, SignedAttestationDatum},
    tel::TEL,
};
use base64::URL_SAFE;
use jolocom_native_utils::did_document::{state_to_did_document, DIDDocument};
use keri::{
    derivation::self_addressing::SelfAddressing,
    event::sections::seal::EventSeal,
    prefix::{IdentifierPrefix, Prefix},
    signer::KeyManager,
    state::IdentifierState,
};

pub mod entity;

use crate::{
    communication::tcp_communication::TCPCommunication,
    controller::entity::Entity,
    error::Error,
    tel::{
        tel_event::{Operation, TelEvent},
        tel_manager::TelManager,
    },
};

#[derive(Debug)]
pub enum SignatureState {
    Ok,
    Wrong,
    Revoked,
}

#[derive(Clone)]
pub struct SharedController {
    pub controller: Arc<Mutex<Controller>>,
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

    pub fn get_current_pk(&self) -> Vec<u8> {
        let e = self.controller.lock().unwrap();
        e.get_current_pk()
        
    }

    pub fn get_next_pk(&self) -> Vec<u8> {
        let e = self.controller.lock().unwrap();
        e.get_next_pk()
        
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

    pub fn verify_vc(
        &self,
        signed_datum: &SignedAttestationDatum,
    ) -> Result<SignatureState, Error> {
        let e = self.controller.lock().unwrap();
        e.verify_vc(signed_datum)
    }

    // Returns signature of last vc.
    pub fn issue_vc(&self, ad_str: &str) -> Result<SignedAttestationDatum, Error> {
        let mut e = self.controller.lock().unwrap();
        let ad = serde_json::from_str(ad_str).unwrap();
        e.issue_vc(&ad)
    }

    pub fn revoke_vc(&self, msg: &str) -> Result<(), Error> {
        let mut e = self.controller.lock().unwrap();
        let ad: AttestationDatum = serde_json::from_str(&msg).unwrap();
        e.revoke_vc(&ad)
    }

    pub fn sign_message(&self, msg: &str) -> Result<SignedAttestationDatum, Error> {
        let pref = self.get_prefix()?;
        let ad = AttestationDatum::new(msg, &pref, vec![]);
        let vc_str = serde_json::to_string(&ad)
            .map_err(|_e| Error::Generic("Can't serialize attestation datum".into()))?;
        let signature = self.sign(&vc_str)?;
        ad.attach_signature(signature)
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

    /// Make Transaction Event Log event.
    ///
    /// Construct TEL event for given operation and sign it.
    fn make_tel_event(&self, operation: Operation) -> Result<TelEvent, Error> {
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

        // Then create tel event with that seal.
        let mut tel_ev = TelEvent::new(event_seal, operation);
        // Sign this event with current keys.
        let msg = serde_json::to_vec(&tel_ev).unwrap();
        let signature = self.sign(from_utf8(&msg).unwrap())?;
        tel_ev.attach_signature(&signature);

        Ok(tel_ev)
    }

    pub fn issue_vc(&mut self, vc: &AttestationDatum) -> Result<SignedAttestationDatum, Error> {
        // Sign vc.
        let vc_str = serde_json::to_string(&vc)
            .map_err(|_e| Error::Generic("Can't serialize attestation datum".into()))?;
        let signature = self.sign(&vc_str)?;
        let signed_vc = vc.attach_signature(signature);

        // Append interaction event to KEL.
        self.main_entity.append(&vc_str)?;

        let vc_digest = blake3::hash(&vc_str.as_bytes()).as_bytes().to_vec();
        let issuance_event = self.make_tel_event(Operation::Issue)?;

        // Update tels.
        self.tels.process_tel_event(&vc_digest, issuance_event)?;
        signed_vc
    }

    pub fn revoke_vc(&mut self, vc: &AttestationDatum) -> Result<(), Error> {
        let vc_str = serde_json::to_string(&vc)
            .map_err(|_e| Error::Generic("Can't serialize attestation datum".into()))?;

        // Append interaction event to KEL.
        self.main_entity.append(&vc_str)?;

        let vc_digest = blake3::hash(&vc_str.as_bytes()).as_bytes().to_vec();
        let revocation_event = self.make_tel_event(Operation::Revoke)?;

        // Update tels.
        self.tels.process_tel_event(&vc_digest, revocation_event)?;
        Ok(())
    }

    pub fn verify_vc(
        &self,
        signed_datum: &SignedAttestationDatum,
    ) -> Result<SignatureState, Error> {
        let attestation_datum = signed_datum.get_attestation_datum()?;
        let issuer = signed_datum.get_issuer()?;
        let signature = signed_datum.get_signature()?;

        // Make sure that issuer kel is in db
        {
            self.get_state(&issuer.parse::<IdentifierPrefix>()?, &self.main_entity)?;
        }

        // Ask issuer for tel
        let address = self.comm.get_address_for_prefix(&issuer)?.unwrap();
        let tel: TEL = {
            let tel_vec = TCPCommunication::ask_for_tel(attestation_datum.as_bytes(), &address)?;
            let tel_str = from_utf8(&tel_vec).map_err(|e| Error::Generic(e.to_string()))?;
            serde_json::from_str(tel_str.trim()).map_err(|e| Error::Generic(e.to_string()))?
        };

        self.main_entity
            .verify_vc(attestation_datum.as_bytes(), &signature, &tel)
    }

    pub fn sign_message(&mut self, msg: &str) -> Result<Vec<u8>, Error> {
        let attestation_datum = AttestationDatum::new(msg, &self.main_entity.get_prefix()?, vec![]);
        let signed_attestation_datum = self.issue_vc(&attestation_datum)?;

        signed_attestation_datum.get_signature()
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

    pub fn get_prefix(&self) -> Result<String, Error> {
        self.main_entity.get_prefix()
    }

    pub fn get_current_pk(&self) -> Vec<u8> {
        self.main_entity.wallet.public_key().0.clone()
    }
    
    pub fn get_next_pk(&self) -> Vec<u8> {
        self.main_entity.wallet.next_public_key().0.clone()
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
        let msg = "Some message";

        let attestation_datum = AttestationDatum::new(msg, &cont.main_entity.get_prefix()?, vec![]);
        let signed_attestation_datum = cont.issue_vc(&attestation_datum)?;
        let ad_str = signed_attestation_datum.get_attestation_datum()?;
        let vc_signature = signed_attestation_datum.get_signature()?;

        let vc_digest = blake3::hash(ad_str.as_bytes()).as_bytes().to_vec();

        let vc_state = cont.tels.get_state(&vc_digest)?;
        assert!(matches!(vc_state, TelState::Issued(_)));

        let ver = {
            let tel = cont.tels.get_tel(&vc_digest)?;
            cont.main_entity
                .verify_vc(ad_str.as_bytes(), &vc_signature, tel)?
        };
        assert!(matches!(ver, SignatureState::Ok));

        // Rotate keys and verify vc again.
        cont.update_keys()?;
        let ver = {
            let tel = cont.tels.get_tel(&vc_digest)?;
            cont.main_entity
                .verify_vc(ad_str.as_bytes(), &vc_signature, tel)?
        };
        assert!(matches!(ver, SignatureState::Ok));

        cont.revoke_vc(&attestation_datum)?;

        let vc_state = cont.tels.get_state(&vc_digest)?;
        assert!(matches!(vc_state, TelState::Revoked));

        let tel = cont.tels.get_tel(&vc_digest)?;
        let ver = cont
            .main_entity
            .verify_vc(ad_str.as_bytes(), &vc_signature, tel)?;
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
        let msg = "Some message";
        let ad = AttestationDatum::new(msg, &prefix, vec![]);

        let signed_ad = cont.issue_vc(&ad)?;
        cont.update_keys()?;

        let issuer_state = cont.main_entity.get_state_for_prefix(&prefix.parse()?)?;

        let db_dir = tempdir()?;
        let db_path = db_dir.path().to_str().unwrap();
        let issuer = SharedController::from_controller(cont)?;
        issuer.clone().run()?;

        let shared_asker = SharedController::new(db_path, "localhost:3232", &adr_store_path)?;
        shared_asker.clone().run()?;

        let ver = shared_asker.verify_vc(&signed_ad)?;
        assert!(matches!(ver, SignatureState::Ok));

        let issuer_state_in_asker = shared_asker
            .controller
            .lock()
            .unwrap()
            .main_entity
            .get_state_for_prefix(&prefix.parse()?)?;
        assert_eq!(issuer_state.unwrap().sn, issuer_state_in_asker.unwrap().sn);

        issuer.revoke_vc(&serde_json::to_string(&ad).unwrap())?;
        let ver = shared_asker.verify_vc(&signed_ad)?;
        assert!(matches!(ver, SignatureState::Revoked));

        Ok(())
    }
}
