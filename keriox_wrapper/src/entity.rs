use crate::error::Error;
use crate::talking_kerl::TalkingKerl;
use crate::wallet_wrapper::WalletWrapper;
use jolocom_native_utils::did_document::state_to_did_document;
use keri::{
    database::lmdb::LmdbEventDatabase,
    keri::Keri,
    prefix::{IdentifierPrefix, Prefix},
};
use keri::{derivation::basic::Basic, prefix::BasicPrefix};
use std::{path::Path};
use ursa::keys::PublicKey;

pub enum KeyType {
    Ed25519Sha512,
}

pub struct Key {
    key: Vec<u8>,
    key_type: KeyType,
}

impl Key {
    pub fn new(key: Vec<u8>, key_type: KeyType) -> Key {
        Self { key, key_type }
    }
    pub fn derive_key_prefix(&self) -> BasicPrefix {
        let pk = PublicKey(self.key.clone());
        match self.key_type {
            KeyType::Ed25519Sha512 => Basic::Ed25519.derive(pk),
        }
    }
}

pub struct Entity {
    kerl: TalkingKerl,
    keri: Keri<LmdbEventDatabase, WalletWrapper>,
}

impl Entity {
    pub fn new(db_path: &str, address: &str, seeds: &str, address_store_path: &str) -> Entity {
        let seeds = serde_json::from_str(seeds).unwrap();
        let db = LmdbEventDatabase::new(Path::new(db_path)).unwrap();
        let mut wallet = WalletWrapper::new();
        wallet.incept_wallet_from_seed(seeds).unwrap();
        let mut keri = Keri::new(db, wallet, IdentifierPrefix::default()).unwrap();
        let icp = keri.incept().unwrap(); //process(icp.as_bytes());
        let prefix = icp.event_message.event.prefix.to_str();

        let talking_kerl = TalkingKerl::new(&prefix, address, address_store_path).unwrap();
        Self {
            kerl: talking_kerl,
            keri,
        }
    }

    pub fn get_did_doc(&self, id: &str) -> Result<String, Error> {
        let pref = id.parse().unwrap();
        let state = self.kerl.get_state(&pref, &self.keri)?;
        Ok(serde_json::to_string(&state_to_did_document(state.unwrap(), "keri")).unwrap())
    }

    pub fn update_keys(&mut self) -> Result<(), Error> {
        self.keri.rotate()?;
        Ok(())
    }

    pub fn append(&mut self, msg: &str) -> Result<(), Error> {
        let payload = if msg.is_empty() { None } else { Some(msg) };
        self.keri.make_ixn(payload)?;
        Ok(())
    }

    pub fn get_kerl(&self) -> Result<String, Error> {
        let kerl = self
            .keri
            .get_kerl()
            .map_err(|e| Error::KeriError(e))?
            .unwrap_or(vec![]);

        Ok(String::from_utf8(kerl).unwrap())
    }

    pub fn get_prefix(&self) -> String {
        self.keri.get_state().unwrap().unwrap().prefix.to_str()
    }

    pub fn run(&self) -> Result<(), Error> {
        self.kerl.run(&self.kerl.get_address(), &self.keri)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_prefix_change() -> Result<(), Error> {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let seeds = "[
            \"rwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc=\",
            \"6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q=\",]";
        // "cwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y=",
        // "lntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8=",
        // "1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E=",
        // "KuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc=",
        // "xFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw=",
        // "Lq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY="
        let _ent = Entity::new(path, "localhost:3333", &seeds.trim(), ".");

        // assert_eq!(ent.prefix, None);

        Ok(())
    }
}
