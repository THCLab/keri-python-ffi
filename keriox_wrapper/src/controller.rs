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
    pub fn new(db_path: &str, address: &str, address_store_path: &str) -> Result<Self, Error> {
        Ok(Self {
            controller: Arc::new(Mutex::new(Controller::new(
                db_path,
                address,
                address_store_path,
            ))),
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
}

pub struct Controller {
    main_entity: Entity,
    comm: TCPCommunication,
    entities: HashMap<String, Entity>,
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

    pub fn get_kerl(&self) -> Result<Vec<u8>, Error> {
        self.main_entity.get_kerl()
    }

    pub fn get_did_doc(&self, id: &str, ent: &Entity) -> Result<DIDDocument, Error> {
        let pref = id.parse().map_err(|e| Error::KeriError(e))?;
        let state = self
            .get_state(&pref, ent)?
            .ok_or(Error::Generic("There is no state.".into()))?;
        Ok(state_to_did_document(state, "keri"))
    }

    pub fn run(controller: Arc<Mutex<Controller>>) -> Result<(), Error> {
        let address = {
            let cont = controller.lock().unwrap();
            cont.comm.get_address()
        };
        thread::spawn(move || {
            TCPCommunication::run(address, controller).unwrap();
        });
        Ok(())
    }

    pub fn parse_message(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let msg_str = from_utf8(message).map_err(|e| Error::Generic(e.to_string()))?;
        let split: Vec<_> = msg_str.split_whitespace().collect();

        println!(
            "{}",
            TCPCommunication::format_event_stream(split[1].as_bytes(), true)
        );
        let ent = if split[0] == self.main_entity.get_prefix().unwrap() {
            &self.main_entity
        } else {
            self.entities.get(split[0]).unwrap()
        };
        ent.respond(split[1].as_bytes())
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
}
