use crate::error::Error;
use crate::tcp_communication::TCPCommunication;
use crate::wallet_wrapper::WalletWrapper;
use base64::URL_SAFE;
use jolocom_native_utils::did_document::{state_to_did_document, DIDDocument};
use keri::{
    database::lmdb::LmdbEventDatabase,
    keri::Keri,
    prefix::{IdentifierPrefix, Prefix},
    signer::KeyManager,
};
use keri::{derivation::basic::Basic, prefix::BasicPrefix};
use std::path::Path;
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
    comm: TCPCommunication,
    keri: Keri<LmdbEventDatabase, WalletWrapper>,
    wallet: WalletWrapper,
}

impl Entity {
    pub fn new(db_path: &str, address: &str, address_store_path: &str) -> Result<Entity, Error> {
        let db = LmdbEventDatabase::new(Path::new(db_path))
            .map_err(|e| Error::Generic(e.to_string()))?;
        let enc_wallet = WalletWrapper::new_encrypted_wallet("pass")?;
        let mut keri = Keri::new(
            db,
            WalletWrapper::to_wallet(enc_wallet.clone(), "pass")?,
            IdentifierPrefix::default(),
        )?;
        let icp = keri.incept()?; //process(icp.as_bytes());

        let prefix = icp.event_message.event.prefix.to_str();
        let wallet = WalletWrapper::to_wallet(enc_wallet, "pass")?;

        let talking_kerl = TCPCommunication::new(&prefix, address, address_store_path)?;
        Ok(Self {
            comm: talking_kerl,
            keri,
            wallet,
        })
    }

    pub fn new_from_seeds(
        db_path: &str,
        address: &str,
        seeds: &str,
        address_store_path: &str,
    ) -> Result<Entity, Error> {
        let seeds: Vec<&str> =
            serde_json::from_str(seeds).map_err(|e| Error::Generic(e.to_string()))?;
        let db = LmdbEventDatabase::new(Path::new(db_path))
            .map_err(|e| Error::Generic(e.to_string()))?;
        let wallet = WalletWrapper::incept_wallet_from_seed(seeds.clone())?;
        let mut keri = Keri::new(db, wallet, IdentifierPrefix::default())?;
        let icp = keri.incept()?; //process(icp.as_bytes());
        let prefix = icp.event_message.event.prefix.to_str();

        let talking_kerl = TCPCommunication::new(&prefix, address, address_store_path)?;
        Ok(Self {
            comm: talking_kerl,
            keri,
            wallet: WalletWrapper::incept_wallet_from_seed(seeds)?,
        })
    }

    pub fn get_did_doc(&self, id: &str) -> Result<String, Error> {
        let pref = id.parse().map_err(|e| Error::KeriError(e))?;
        let state = self
            .comm
            .get_state(&pref, &self.keri)?
            .ok_or(Error::Generic("There is no state.".into()))?;
        serde_json::to_string(&state_to_did_document(state, "keri"))
            .map_err(|e| Error::Generic(e.to_string()))
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

        String::from_utf8(kerl).map_err(|e| Error::StringFromUtf8Error(e))
    }

    pub fn get_prefix(&self) -> Result<String, Error> {
        self.keri
            .get_state()
            .map_err(|e| Error::KeriError(e))?
            .map(|s| s.prefix.to_str())
            .ok_or(Error::Generic("There is no prefix".into()))
    }

    pub fn run(&self) -> Result<(), Error> {
        self.comm.run(&self.comm.get_address(), &self.keri)?;
        Ok(())
    }

    pub fn sign(&self, msg: &str) -> Result<Vec<u8>, Error> {
        self.wallet
            .sign(&msg.as_bytes().to_vec())
            .map_err(|e| Error::KeriError(e))
    }

    pub fn verify(&self, issuer_id: &str, msg: &str, signature: &str) -> Result<bool, Error> {
        let did = self.get_did_doc(issuer_id)?;
        let ddoc: DIDDocument =
            serde_json::from_str(&did).map_err(|e| Error::Generic(e.to_string()))?;

        let signature_vec = base64::decode_config(signature, URL_SAFE)?;

        self.wallet
            .verify_with_key(
                &ddoc.verification_methods[0],
                msg.as_bytes(),
                &signature_vec,
            )
            .map_err(|e| Error::KeriError(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir};

    #[test]
    fn test_signing() -> Result<(), Error> {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let addresses_path = [path, "addresses"].join("");
        let seeds = "[
            \"rwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc=\",
            \"6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q=\"]";
        // "cwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y=",
        // "lntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8=",
        // "1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E=",
        // "KuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc=",
        // "xFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw=",
        // "Lq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY="
        let mut ent = Entity::new_from_seeds(path, "localhost:3333", seeds.trim(), &addresses_path)?;

        let msg = "hello there!";
        let signature = ent.sign(msg)?;
        let signature_b64 = base64::encode_config(signature, URL_SAFE);

        let v = ent.verify(&ent.get_prefix()?, msg, &signature_b64)?;
        assert!(v);

        ent.update_keys()?;
        let v = ent.verify(&ent.get_prefix()?, msg, &signature_b64)?;
        assert!(!v);

        Ok(())
    }

    #[test]
    fn test_incepting() -> Result<(), Error> {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let addresses_path = [path, "addresses"].join("");

        let _ent = Entity::new(path, "localhost:3333", &addresses_path)?;

        Ok(())
    }
}
