use crate::wallet_wrapper::WalletWrapper;
use crate::{error::Error, tel::tel_event::TelState, tel::TEL};
use base64::URL_SAFE;
use jolocom_native_utils::did_document::DIDDocument;
use keri::{
    database::lmdb::LmdbEventDatabase,
    event::sections::{seal::EventSeal, KeyConfig},
    event_message::parse,
    keri::Keri,
    prefix::{IdentifierPrefix, Prefix},
    signer::KeyManager,
    state::{EventSemantics, IdentifierState},
};
use std::{convert::TryInto, path::Path};

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

    // Works only for currnet keys.
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

    /// Returns current Key Config associated with given event seal.
    /// Note: Similar to function `get_keys_at_sn` in processor module in keriox,
    /// but without processor.
    // TODO should be in keriox, probably.
    fn get_keys_at_sn(seal: &EventSeal, kel: &[u8]) -> Result<KeyConfig, Error> {
        let sn = seal.sn;
        let pref = seal.prefix.clone();
        let s = parse::signed_event_stream(&kel).unwrap().1;

        let state = s
            .into_iter()
            .take_while(|ev| match ev {
                parse::Deserialized::Event(e) => {
                    e.event.event.event.prefix == pref && e.event.event.event.sn <= sn
                }
                parse::Deserialized::Vrc(_) => true,
                parse::Deserialized::Rct(_) => true,
            })
            .fold(IdentifierState::default(), |st, e| {
                let em = match e {
                    parse::Deserialized::Event(e) => e.event.event.apply_to(st).unwrap(),
                    parse::Deserialized::Vrc(_) => st,
                    parse::Deserialized::Rct(_) => st,
                };
                em
            });

        // Check if seal digest and digest of last state event match.
        if seal.event_digest.derivation.derive(&state.last) != seal.event_digest {
            Err(Error::Generic(
                "seal digest doesnt match last event's digest".into(),
            ))
        } else {
            Ok(state.current)
        }
    }

    pub fn verify_vc(&self, vc: &[u8], signature: &[u8], tel: &TEL) -> Result<bool, Error> {
        match tel.get_state() {
            TelState::NotIsuued => Ok(false),
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
                Ok(verification)
            }
            TelState::Revoked => Ok(false),
        }
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
        let _addresses_path = [path, "addresses"].join("");
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
        let _signature_b64 = base64::encode_config(signature, URL_SAFE);

        // let v = ent.verify(&ent.get_prefix()?, msg, &signature_b64)?;
        // assert!(v);

        ent.update_keys()?;
        // let v = ent.verify(&ent.get_prefix()?, msg, &signature_b64)?;
        // assert!(!v);

        Ok(())
    }
}
