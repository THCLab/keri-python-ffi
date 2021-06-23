use crate::{controller::SignatureState, kerl::KERL};
use crate::{error::Error, tel::tel_event::TelState, tel::TEL};
use base64::URL_SAFE;
use keri::signer::CryptoBox;
use keri::{
    database::lmdb::LmdbEventDatabase,
    keri::Keri,
    prefix::{IdentifierPrefix, Prefix},
    signer::KeyManager,
    state::IdentifierState,
};
use std::{convert::TryInto, path::Path};

pub struct Entity {
    keri: KERL<LmdbEventDatabase>,
    pub wallet: CryptoBox,
}

impl Entity {
    pub fn new(db_path: &str) -> Result<Entity, Error> {
        let db = LmdbEventDatabase::new(Path::new(db_path))
            .map_err(|e| Error::Generic(e.to_string()))?;
        let wallet = CryptoBox::new()?;
        let mut keri = KERL::new(db, IdentifierPrefix::default())?;
        keri.incept(&wallet)?;

        Ok(Self { keri, wallet })
    }

    // pub fn new_from_seeds(db_path: &str, seeds: &str) -> Result<Entity, Error> {
    //     let seeds: Vec<&str> =
    //         serde_json::from_str(seeds).map_err(|e| Error::Generic(e.to_string()))?;
    //     let db = LmdbEventDatabase::new(Path::new(db_path))
    //         .map_err(|e| Error::Generic(e.to_string()))?;
    //     let wallet = WalletWrapper::incept_wallet_from_seed(seeds.clone())?;
    //     let mut keri = KERL::new(db, IdentifierPrefix::default())?;
    //     keri.incept(&wallet)?;

    //     Ok(Self {
    //         keri,
    //         wallet: WalletWrapper::incept_wallet_from_seed(seeds)?,
    //     })
    // }

    pub fn update_keys(&mut self) -> Result<(), Error> {
        self.keri.rotate(&mut self.wallet)?;
        Ok(())
    }

    pub fn append(&mut self, msg: &str) -> Result<(), Error> {
        let payload = if msg.is_empty() { None } else { Some(msg) };
        self.keri.make_ixn(payload, &self.wallet)?;
        Ok(())
    }

    pub fn get_kerl(&self) -> Result<Vec<u8>, Error> {
        let kerl = self.keri.get_kerl()?.unwrap_or(vec![]);
        Ok(kerl)
    }

    pub fn get_prefix(&self) -> Result<String, Error> {
        self.keri
            .get_state()?
            .map(|s| s.prefix.to_str())
            .ok_or(Error::Generic("There is no prefix".into()))
    }

    pub fn get_state_for_prefix(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        self.keri.get_state_for_prefix(id)
    }

    pub fn respond(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        self.keri
            .respond(msg, &self.wallet)
            .map_err(|e| Error::Generic(e.to_string()))
    }

    pub fn sign(&self, msg: &str) -> Result<Vec<u8>, Error> {
        self.wallet
            .sign(&msg.as_bytes().to_vec())
            .map_err(|e| Error::KeriError(e))
    }

    // Works only for currnet keys.
    pub fn verify(&self, state: IdentifierState, msg: &str, signature: &str) -> Result<bool, Error> {
        let signature_vec = base64::decode_config(signature, URL_SAFE)?;

        // This assumes that there is only one key.
        let bp = state.current.public_keys.get(0).unwrap();
        let key_type = bp.derivation_code();
        let public_key = bp.derivative();
        match key_type.as_str() {
            "D" => {
                use ed25519_dalek::{PublicKey, Signature, Verifier};
                let pk = PublicKey::from_bytes(&public_key).unwrap();
                let array_signature: [u8; 64] = signature.as_bytes().clone().try_into().unwrap();
                let signature = Signature::new(array_signature);
                Ok(pk.verify(msg.as_bytes(), &signature).is_ok())

            },
            _ => todo!()
        }
    }

    pub fn verify_vc(
        &self,
        vc: &[u8],
        signature: &[u8],
        tel: &TEL,
    ) -> Result<SignatureState, Error> {
        match tel.get_state() {
            TelState::NotIsuued => Ok(SignatureState::Wrong),
            TelState::Issued(event_seal) => {
                let state = self.keri.get_state_for_seal(&event_seal);
                let keys = match state? {
                    Some(state) => state.current,
                    None => return Err(Error::Generic("There is no keys".into())),
                };

                // This assumes that there is only one key.
                let bp = keys.public_keys.get(0).unwrap();
                let key_type = bp.derivation_code();
                let public_key = bp.derivative();
                let verification = match key_type.as_str() {
                    "D" => {
                        // With dalek.
                        use ed25519_dalek::{PublicKey, Signature, Verifier};
                        let pk = PublicKey::from_bytes(&public_key).unwrap();
                        let array_signature: [u8; 64] = signature.clone().try_into().unwrap();
                        let signature = Signature::new(array_signature);
                        pk.verify(vc, &signature).is_ok()

                        // With ursa.
                        // let pub_key = PublicKey {0: public_key.to_vec()};
                        // let ed = ursa::signatures::ed25519::Ed25519Sha512::new();
                        // let msg = &serde_json::to_vec(&self).unwrap();
                        // ed.verify(msg, &self.signature, &pub_key).map_err(|e| Error::Generic(e.to_string()))?
                    }
                    _ => false,
                };
                Ok(if verification {
                    SignatureState::Ok
                } else {
                    SignatureState::Wrong
                })
            }
            TelState::Revoked => Ok(SignatureState::Revoked),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_signing() -> Result<(), Error> {
        // let dir = tempdir().unwrap();
        // let path = dir.path().to_str().unwrap();
        // let _addresses_path = [path, "addresses"].join("");
        // let seeds = "[
        //     \"rwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc=\",
        //     \"6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q=\"]";
        // // "cwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y=",
        // // "lntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8=",
        // // "1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E=",
        // // "KuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc=",
        // // "xFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw=",
        // // "Lq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY="
        // let mut ent = Entity::new_from_seeds(path, seeds.trim())?;

        // let msg = "hello there!";
        // let signature = ent.sign(msg)?;
        // let _signature_b64 = base64::encode_config(signature, URL_SAFE);

        // // let v = ent.verify(&ent.get_prefix()?, msg, &signature_b64)?;
        // // assert!(v);

        // ent.update_keys()?;
        // // let v = ent.verify(&ent.get_prefix()?, msg, &signature_b64)?;
        // // assert!(!v);

        Ok(())
    }
}
