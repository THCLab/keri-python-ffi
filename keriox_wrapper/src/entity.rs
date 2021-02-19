use crate::error::Error;
use crate::event_generator;
use crate::kerl::Kerl;
use crate::talking_kerl::TalkingKerl;
use crate::{
    did_document::state_to_did_document,
};
use keri::prefix::{AttachedSignaturePrefix, IdentifierPrefix, Prefix};
use keri::{derivation::basic::Basic, event_message::parse::message, prefix::BasicPrefix};
use keri::{derivation::self_signing::SelfSigning, event::event_data::EventData};
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
    address: String,
    prefix: Option<IdentifierPrefix>,
    kerl: TalkingKerl,
}

impl Entity {
    pub fn new(db_path: &str, id: &str, address: &str) -> Entity {
        let kerl = Kerl::new(db_path).unwrap();
        let talking_kerl = TalkingKerl::new(kerl).unwrap();
        let prefix: Option<IdentifierPrefix> = if id.is_empty() { None } else { id.parse().ok() };
        Self {
            address: address.to_string(),
            prefix,
            kerl: talking_kerl,
        }
    }

    pub fn get_did_doc(&self, id: &str, adress: &str) -> Result<String, Error> {
        let pref = id.parse().unwrap();
        let state = self.kerl.get_state(&pref, adress)?;
        Ok(serde_json::to_string(&state_to_did_document(state.unwrap(), "keri")).unwrap())
    }

    pub fn incept_keys(&mut self, pk: &Key, nxt_pk: &Key) -> Result<Vec<u8>, Error> {
        let (_, icp) = event_generator::make_icp(&pk, &nxt_pk, None)?;
        Ok(icp)
    }

    pub fn update_keys(&self, pk: &Key, next_pk: &Key) -> Result<Vec<u8>, Error> {
        let state = self
            .kerl
            .get_state(
                &self.prefix.clone().unwrap_or(IdentifierPrefix::default()),
                &self.address,
            )?
            .unwrap();
        event_generator::make_rot(pk, next_pk, state)
    }

    pub fn confirm_key_update(
        &mut self,
        ser_event: &[u8],
        signature: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let ev = message(ser_event).unwrap().1.event;
        let sigged = ev.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature.to_vec(),
            0,
        )]);

        self.kerl.proccess(&sigged.serialize()?)?;

        if let EventData::Icp(_) = ev.event.event_data {
            self.prefix = Some(ev.event.prefix.clone());
            self.kerl.set_id(ev.event.prefix.clone());
        }

        Ok(sigged.serialize()?)
    }

    pub fn get_prefix(&self) -> String {
        self.prefix
            .clone()
            .unwrap_or(IdentifierPrefix::default())
            .to_str()
            .into()
    }

    pub fn run(&self) -> Result<(), Error>{
        self.kerl.run(&self.prefix.clone().unwrap(), &self.address)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::URL_SAFE;
    use tempfile::tempdir;

    #[test]
    fn test_prefix_change() -> Result<(), Error> {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut ent = Entity::new(
            path,
            "localhost:3333",
            &IdentifierPrefix::default().to_str(),
        );

        assert_eq!(ent.prefix, None);

        let curr_pk = Key::new(
            base64::decode_config(b"2ypJuIahT7YHa81gVRW7snp8Ug7TQJJx1x9iDWErl80=", URL_SAFE)?,
            KeyType::Ed25519Sha512,
        );
        let next_pk = Key::new(
            base64::decode_config(b"8hFAoIYdBrEJATIcVTU2g-PlR7hWPLaY2N-fRsk7DKU=", URL_SAFE)?,
            KeyType::Ed25519Sha512,
        );
        let icp = ent.incept_keys(&curr_pk, &next_pk)?;

        // Event was just generated, not processed so prefix shouldn't be updated.
        assert_eq!(ent.prefix, None);

        let signature = base64::decode_config(b"YpccjbwxPDyZfB-ifkuGTkepRuxFVyQ7gjB4weqmsL-RQxGquFVlRgpmUACxpjiQjnH6H8zwuXodnvvzHNPFCw==", URL_SAFE)?;
        ent.confirm_key_update(&icp, &signature)?;

        // Entity get signed inception event, should update prefix.
        assert_eq!(
            ent.prefix,
            "D2ypJuIahT7YHa81gVRW7snp8Ug7TQJJx1x9iDWErl80".parse().ok()
        );

        let new_next_pk = Key::new(
            base64::decode_config(b"usccDUmnbzJL8HLJo6RpGPkS6NApcUZU0v5qTdAvv2s=", URL_SAFE)?,
            KeyType::Ed25519Sha512,
        );
        let rot = ent.update_keys(&next_pk, &new_next_pk)?;

        let signature = base64::decode_config(b"3tmbRYD61uXuPYHFlj3FAJOMSYtgz28gg98lPA1eASV6x-AFUsG_pB5_GV-ZExr3Bcv9xP8p_JedWFlTX5ylAQ==", URL_SAFE)?;
        ent.confirm_key_update(&rot, &signature)?;

        // Prefix can't change after processing rotation event.
        assert_eq!(
            ent.prefix,
            "D2ypJuIahT7YHa81gVRW7snp8Ug7TQJJx1x9iDWErl80".parse().ok()
        );

        // println!("{}", ent.get_did_doc("D7YNuH34RaqAPg1gaNia5mzxI7Av20RRjYM2pBksWhJw", "localhost:5621")?);

        dir.close().unwrap();
        Ok(())
    }
}
