use std::{collections::HashMap, error::Error};

use rustbreak::{deser::Ron, FileDatabase};


pub struct AddressProvider {
    storage: FileDatabase<HashMap<String, String>, Ron>,
}

impl AddressProvider {
    pub fn new(db_path: &str) -> AddressProvider {
        let db: FileDatabase<HashMap<String, String>, Ron> =
            FileDatabase::load_from_path_or(db_path, HashMap::new()).unwrap();

        Self { storage: db }
    }
    pub fn register(&self, id: &str, address: &str) -> Result<(), Box<dyn Error>> {
        self.storage
            .write(|db| {
                db.insert(id.to_string(), address.to_string());
            })?;

        self.storage.save()?;

        Ok(())
    }

    pub fn get_address(&self, id: &str) -> Result<Option<String>, Box<dyn Error>> {
        let mut s = None;
        self.storage
            .read(|db| {
                s = db.get(id).map(|s| s.to_owned());
            })?;

        Ok(s)
    }
}
