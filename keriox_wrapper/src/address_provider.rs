use std::collections::HashMap;

use crate::error::Error;

pub struct AddressProvider {
    storage: HashMap<String, String>,
}

impl AddressProvider {
    pub fn new() -> AddressProvider {
        Self {
            storage: HashMap::new(),
        }
    }
    pub fn register(&mut self, id: String, address: String) -> Result<(), Error> {
        self.storage.insert(id, address);
        Ok(())
    }

    pub fn get_address(&self, id: &str) -> Result<Option<&String>, Error> {
        Ok(self.storage.get(id))
    }
}
