use std::{
    collections::HashMap,
    str::from_utf8,
    sync::{Arc, Mutex},
    thread,
};

use jolocom_native_utils::did_document::{state_to_did_document, DIDDocument};
use keri::{
    prefix::{IdentifierPrefix, Prefix},
    state::IdentifierState,
};

use crate::{entity::Entity, error::Error, tcp_communication::TCPCommunication};

#[derive(Clone)]
pub struct SharedController {
    controller: Arc<Mutex<Controller>>,
}

impl SharedController {
    pub fn new(address: &str, address_store_path: &str) -> Result<Self, Error> {
        Ok(Self {
            controller: Arc::new(Mutex::new(Controller::new(address, address_store_path))),
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
        // Get random entity from entities hashmap.
        // TODO
        let verifier = e.entities.iter().next().unwrap().1;
        Ok(serde_json::to_string_pretty(&e.get_did_doc(id, verifier)?).unwrap())
    }

    pub fn update_keys(&mut self, id: &str) -> Result<(), Error> {
        let mut e = self.controller.lock().unwrap();
        e.update_keys(id)
    }

    pub fn add_entity(&mut self, db_path: &str) {
        let mut e = self.controller.lock().unwrap();
        e.new_entity(db_path)
    }

    // pub fn append(&mut self, msg: &str) -> Result<(), Error> {
    //     let mut e = self.ent.lock().unwrap();
    //     e.append(msg)
    // }

    pub fn get_kerl_of_prefix(&self, id: &str) -> Result<String, Error> {
        let e = self.controller.lock().unwrap();
        Ok(TCPCommunication::format_event_stream(
            &e.get_kerl_of(id)?,
            false,
        ))
    }

    pub fn get_prefixes(&self) -> Result<Vec<String>, Error> {
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

    pub fn verify(&self, issuer_id: &str, msg: &str, signature: &str) -> Result<bool, Error> {
        let e = self.controller.lock().unwrap();
        e.verify(issuer_id, msg, signature)
    }
}

pub struct Controller {
    comm: TCPCommunication,
    entities: HashMap<String, Entity>,
}

impl Controller {
    pub fn new(adr: &str, adr_store_path: &str) -> Self {
        let comm = TCPCommunication::new(adr, adr_store_path).unwrap();
        Controller {
            comm,
            entities: HashMap::new(),
        }
    }

    pub fn new_entity(&mut self, db_path: &str) {
        let ent = Entity::new(db_path).unwrap();
        let id = ent.get_prefix().unwrap();
        self.comm.register(&id).unwrap();
        self.entities.insert(id, ent);
    }

    pub fn sign_by(&self, id: &str, msg: &str) -> Result<Vec<u8>, Error> {
        let ent = self.entities.get(id).unwrap();
        ent.sign(msg)
    }

    pub fn verify(&self, issuer_id: &str, msg: &str, signature: &str) -> Result<bool, Error> {
        // Get random entity from entities hashmap.
        let verifier = self.entities.iter().next().unwrap().1;
        let ddoc = self.get_did_doc(issuer_id, verifier)?;

        verifier.verify(&ddoc, msg, signature)
    }

    pub fn update_keys(&mut self, id: &str) -> Result<(), Error> {
        let ent = self.entities.get_mut(id).unwrap();
        ent.update_keys()
    }

    pub fn get_kerl_of(&self, id: &str) -> Result<Vec<u8>, Error> {
        let ent = self.entities.get(id).unwrap();
        ent.get_kerl()
    }

    pub fn get_did_doc(&self, id: &str, ent: &Entity) -> Result<DIDDocument, Error> {
        let pref = id.parse().map_err(|e| Error::KeriError(e))?;
        let state = self
            .get_state(&pref, ent)?
            .ok_or(Error::Generic("There is no state.".into()))?;
        Ok(state_to_did_document(state, "keri"))
    }

    pub fn run(controller: Arc<Mutex<Controller>>) -> Result<(), Error> {
        let c = controller.clone();
        let cont = c.lock().unwrap();
        let address = cont.comm.get_address();
        thread::spawn(move || {
            TCPCommunication::run(address, controller).unwrap();
        });
        Ok(())
    }

    pub fn parse_message(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        println!("Got to parse:\n{}", from_utf8(message).unwrap());
        let msg_str = from_utf8(message).map_err(|e| Error::Generic(e.to_string()))?;
        let split: Vec<_> = msg_str.split_whitespace().collect();

        println!(
            "{}",
            TCPCommunication::format_event_stream(split[1].as_bytes(), true)
        );

        let ent = self
            .entities
            .get(split[0])
            .unwrap()
            .respond(split[1].as_bytes());
        ent
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
                // .ok_or(Error::Generic("Can't find kerl".into()))?;
                let addr = self
                    .comm
                    .get_address_for_prefix(&id.to_str())?
                    .ok_or(Error::Generic("Can't find address for prefix".into()))?;
                TCPCommunication::send(&kerl, &addr, &id.to_str(), entity)?;
                Ok(entity.get_state_for_prefix(id)?)
            }
        }
    }
}
