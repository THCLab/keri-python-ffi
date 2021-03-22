use std::collections::HashMap;

use rustbreak::{deser::Ron, FileDatabase};

use crate::error::Error;

pub struct AddressProvider {
    storage: FileDatabase<HashMap<String, String>, Ron>,
}

impl AddressProvider {
    pub fn new(db_path: &str) -> Result<AddressProvider, Error> {
        let db: FileDatabase<HashMap<String, String>, Ron> =
            FileDatabase::load_from_path_or(db_path, HashMap::new())
                .map_err(|e| Error::AddressProviderError(e))?;
        Ok(Self { storage: db })
    }
    pub fn register(&self, id: &str, address: &str) -> Result<(), Error> {
        self.storage.write(|db| {
            db.insert(id.to_string(), address.to_string());
        })?;

        self.storage.save()?;

        Ok(())
    }

    pub fn get_address(&self, id: &str) -> Result<Option<String>, Error> {
        let mut s = None;
        self.storage.read(|db| {
            s = db.get(id).map(|s| s.to_owned());
        })?;

        Ok(s)
    }
}
