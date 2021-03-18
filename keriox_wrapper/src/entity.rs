use crate::error::Error;
use crate::wallet_wrapper::WalletWrapper;
use base64::URL_SAFE;
use jolocom_native_utils::did_document::DIDDocument;
use keri::{
    database::lmdb::LmdbEventDatabase,
    keri::Keri,
    prefix::{IdentifierPrefix, Prefix},
    signer::KeyManager,
    state::IdentifierState,
};
use std::path::Path;

pub struct Entity {
    keri: Keri<LmdbEventDatabase, WalletWrapper>,
    wallet: WalletWrapper,
}

impl Entity {
    pub fn new(db_path: &str) -> Result<Entity, Error> {
        let db = LmdbEventDatabase::new(Path::new(db_path))
            .map_err(|e| Error::Generic(e.to_string()))?;
        let enc_wallet = WalletWrapper::new_encrypted_wallet("pass")?;
        let mut keri = Keri::new(
            db,
            WalletWrapper::to_wallet(enc_wallet.clone(), "pass")?,
            IdentifierPrefix::default(),
        )?;
        keri.incept()?;

        let wallet = WalletWrapper::to_wallet(enc_wallet, "pass")?;

        Ok(Self { keri, wallet })
    }

    pub fn new_from_seeds(db_path: &str, seeds: &str) -> Result<Entity, Error> {
        let seeds: Vec<&str> =
            serde_json::from_str(seeds).map_err(|e| Error::Generic(e.to_string()))?;
        let db = LmdbEventDatabase::new(Path::new(db_path))
            .map_err(|e| Error::Generic(e.to_string()))?;
        let wallet = WalletWrapper::incept_wallet_from_seed(seeds.clone())?;
        let mut keri = Keri::new(db, wallet, IdentifierPrefix::default())?;
        keri.incept()?;

        Ok(Self {
            keri,
            wallet: WalletWrapper::incept_wallet_from_seed(seeds)?,
        })
    }

    pub fn update_keys(&mut self) -> Result<(), Error> {
        self.keri.rotate()?;
        self.wallet.rotate()?;
        Ok(())
    }

    pub fn append(&mut self, msg: &str) -> Result<(), Error> {
        let payload = if msg.is_empty() { None } else { Some(msg) };
        self.keri.make_ixn(payload)?;
        Ok(())
    }

    pub fn get_kerl(&self) -> Result<Vec<u8>, Error> {
        let kerl = self
            .keri
            .get_kerl()
            .map_err(|e| Error::KeriError(e))?
            .unwrap_or(vec![]);
        Ok(kerl)
    }

    pub fn get_prefix(&self) -> Result<String, Error> {
        self.keri
            .get_state()
            .map_err(|e| Error::KeriError(e))?
            .map(|s| s.prefix.to_str())
            .ok_or(Error::Generic("There is no prefix".into()))
    }

    pub fn get_state_for_prefix(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        self.keri
            .get_state_for_prefix(id)
            .map_err(|e| Error::KeriError(e))
    }

    pub fn respond(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        self.keri
            .respond(msg)
            .map_err(|e| Error::Generic(e.to_string()))
    }

    pub fn sign(&self, msg: &str) -> Result<Vec<u8>, Error> {
        self.wallet
            .sign(&msg.as_bytes().to_vec())
            .map_err(|e| Error::KeriError(e))
    }

    pub fn verify(&self, ddoc: &DIDDocument, msg: &str, signature: &str) -> Result<bool, Error> {
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
    use tempfile::tempdir;

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
        let mut ent = Entity::new_from_seeds(path, seeds.trim())?;

        let msg = "hello there!";
        let signature = ent.sign(msg)?;
        let signature_b64 = base64::encode_config(signature, URL_SAFE);

        // let v = ent.verify(&ent.get_prefix()?, msg, &signature_b64)?;
        // assert!(v);

        ent.update_keys()?;
        // let v = ent.verify(&ent.get_prefix()?, msg, &signature_b64)?;
        // assert!(!v);

        Ok(())
    }

    #[test]
    fn test_incepting() -> Result<(), Error> {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let addresses_path = [path, "addresses"].join("");

        let _ent = Entity::new(path)?;

        Ok(())
    }
}
