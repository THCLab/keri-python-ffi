use crate::{controller::Controller, datum::SignedAttestationDatum, error::Error};

use crate::kerl::{event_generator, KERL};
use keri::{
    database::{lmdb::LmdbEventDatabase, EventDatabase},
    event::EventMessage,
    event_message::SignedEventMessage,
    prefix::IdentifierPrefix,
    state::IdentifierState,
};

pub struct Thing {
    kerl: KERL<LmdbEventDatabase>,
    vc_storage: Vec<SignedAttestationDatum>,
}

impl Thing {
    pub fn new(db: LmdbEventDatabase, prefix: IdentifierPrefix) -> Self {
        Thing {
            kerl: KERL::new(db, prefix).unwrap(),
            vc_storage: vec![],
        }
    }

    pub fn add_document(&mut self, document: SignedAttestationDatum) -> Result<(), Error> {
        // Insert document to storage
        self.vc_storage.push(document);

        Ok(())
    }

    pub fn process(
        &mut self,
        event: EventMessage,
        signature: Vec<u8>,
    ) -> Result<SignedEventMessage, Error> {
        self.kerl.process(event, signature)
    }

    pub fn get_datum_list(&self) -> Result<String, Error> {
        let mut out = String::new();
        for datum in self.vc_storage.iter() {
            let hash = base64::encode_config(
                blake3::hash(datum.get_attestation_datum()?.as_bytes())
                    .as_bytes()
                    .to_vec(),
                base64::URL_SAFE,
            );
            out = format!(
                "{}\nvc hash: {},\n vc {}\n",
                out,
                hash,
                serde_json::to_string_pretty(datum).unwrap()
            );
        }
        Ok(out.to_string())
    }

    pub fn get_kerl(&self) -> Result<Option<Vec<u8>>, Error> {
        self.kerl.get_kerl()
    }

    pub fn get_state(&self) -> Result<Option<IdentifierState>, Error> {
        self.kerl.get_state()
    }
}

#[test]
pub fn test_pack() -> Result<(), Error> {
    use std::fs;
    use tempfile::tempdir;
    use tempfile::Builder;

    use crate::communication::tcp_communication::TCPCommunication;
    use crate::controller::Controller;
    use crate::datum::AttestationDatum;
    use event_generator::{Key, KeyType};
    use keri::database::lmdb::LmdbEventDatabase;

    let temp_dir = tempdir().unwrap();
    let adr_store_path = [temp_dir.path().to_str().unwrap(), "adr"].join("");

    // Setup empty pack kerl
    let pack_root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(pack_root.path()).unwrap();
    let pack_db = LmdbEventDatabase::new(pack_root.path()).unwrap();
    let mut pack = Thing::new(pack_db, IdentifierPrefix::default());

    // Setup sender controller
    let sender_db_dir = tempdir().unwrap();
    let sender_db_path = sender_db_dir.path().to_str().unwrap();
    let mut sender = Controller::new(sender_db_path, "localhost:1212", &adr_store_path);
    println!(
        "Sender: {}, current key: {}\n",
        sender.get_prefix()?,
        base64::encode_config(&sender.get_current_pk(), base64::URL_SAFE)
    );

    // Setup courier controller
    let courier_db_dir = tempdir().unwrap();
    let courier_db_path = courier_db_dir.path().to_str().unwrap();
    let mut courier = Controller::new(courier_db_path, "localhost:1200", &adr_store_path);
    println!(
        "Courier: {}, current key: {}\n",
        courier.get_prefix()?,
        base64::encode_config(&courier.get_current_pk(), base64::URL_SAFE)
    );

    // Setup receiver controller
    let receiver_db_dir = tempdir().unwrap();
    let receiver_db_path = receiver_db_dir.path().to_str().unwrap();
    let receiver = Controller::new(receiver_db_path, "localhost:1000", &adr_store_path);

    let receiver_pref = receiver.get_prefix()?;

    // ========================================================
    // Sender fills the sending form
    // Incept pack kel with sender key as current key and courier public key as next.
    let pk = Key::new(sender.get_current_pk(), KeyType::Ed25519Sha512);
    let next_pk = Key::new(courier.get_current_pk(), KeyType::Ed25519Sha512);

    let icp_msg = event_generator::make_icp(&pk, &next_pk, None)?;
    let signature = sender.sign(&String::from_utf8(icp_msg.serialize()?).unwrap())?;
    // Confirm sending the pack by signing icp message
    pack.process(icp_msg, signature)?;

    // Construct confirmation of sending the pack.
    // Insert reciver id in the pack kerl
    let sender_prefix = sender.get_prefix()?;
    // Compute vc related stuff
    let msg = format!("Pack sent to {}", receiver_pref);
    let sender_vc = AttestationDatum::new(&msg, &sender_prefix, vec![]);
    let signed_ad = sender.issue_vc(&sender_vc)?;

    let vc_str = signed_ad.get_attestation_datum()?;
    let ixn = event_generator::make_ixn(Some(&vc_str), pack.kerl.get_state()?.unwrap())?;
    let signature = sender.sign(std::str::from_utf8(&ixn.serialize()?).unwrap())?;
    pack.process(ixn, signature)?;

    // Add document to pack. It adds document to pack vcx store and adds interaction event to pack kerl.
    pack.add_document(signed_ad)?;

    // =========================================================
    // Courier got the pack. Rotate key to storage public key as next.
    // Setup storage controller
    let receiver_db_dir = tempdir().unwrap();
    let receiver_db_path = receiver_db_dir.path().to_str().unwrap();
    let storage = Controller::new(receiver_db_path, "localhost:1200", &adr_store_path);

    let pk = Key::new(courier.get_current_pk(), KeyType::Ed25519Sha512);
    let next_pk = Key::new(storage.get_current_pk(), KeyType::Ed25519Sha512);

    let rotation_event = event_generator::make_rot(&pk, &next_pk, pack.get_state()?.unwrap())?;
    let signature = courier.sign(std::str::from_utf8(&rotation_event.serialize()?).unwrap())?;
    pack.process(rotation_event, signature)?;

    // Compute vc related stuff
    let msg = "I got the pack";
    let ad = AttestationDatum::new(msg, &courier.get_prefix()?, vec![]);

    let signed_ad = courier.issue_vc(&ad).unwrap();

    let vc_str = signed_ad.get_attestation_datum()?;
    let ixn = event_generator::make_ixn(Some(&vc_str), pack.kerl.get_state()?.unwrap())?;
    let signature = courier.sign(std::str::from_utf8(&ixn.serialize()?).unwrap())?;
    pack.process(ixn, signature)?;

    // Append interaction event to pack KEL.
    pack.add_document(signed_ad)?;

    let formatted_kerl = TCPCommunication::format_event_stream(&pack.get_kerl()?.unwrap(), false);

    println!("=========== PACK'S KEL =============\n {}", formatted_kerl);
    println!(
        "==== DOCUMENTS ASSOCIATED WITH THE PACK ======\n {}",
        pack.get_datum_list()?
    );

    Ok(())
}
