use std::{
    fs::OpenOptions,
    io::{self, BufRead, Write},
};

use crate::error::Error;

pub struct AddressProvider {
    db_path: String,
}

impl AddressProvider {
    pub fn new(db_path: &str) -> Result<AddressProvider, Error> {
        Ok(Self {
            db_path: db_path.to_string(),
        })
    }
    pub fn register(&self, id: &str, address: &str) -> Result<(), Error> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .append(true)
            .open(&self.db_path)?;
        file.write_all([id, address, "\n"].join(" ").as_bytes())?;

        Ok(())
    }

    pub fn get_address(&self, id: &str) -> Result<Option<String>, Error> {
        let file = OpenOptions::new().read(true).open(&self.db_path)?;
        let mut lines = io::BufReader::new(file).lines();

        Ok(lines
            .find(|line| line.as_ref().unwrap().starts_with(id))
            .map(|element| match element {
                Ok(el) => el.split(" ").collect::<Vec<_>>()[1].to_owned(),
                Err(_) => "".into(),
            }))
    }
}
