use std::{
    fs,
    io::Read,
    io::Write,
    net::TcpListener,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use keri::{
    database::lmdb::LmdbEventDatabase, event_message::parse::signed_event_stream,
    prefix::IdentifierPrefix, state::IdentifierState,
};

use crate::{controller::SharedController, error::Error, thing::Thing};

use super::tcp_communication::TCPCommunication;
use crate::datum::AttestationDatum;
use crate::datum::SignedAttestationDatum;
use crate::kerl::event_generator;
use crate::kerl::event_generator::{make_icp, Key, KeyType};
use keri::derivation::self_signing::SelfSigning;
use keri::prefix::AttachedSignaturePrefix;
use keri::state::EventSemantics;
use std::net::TcpStream;
use std::thread;

pub struct SharedThing {
    thing: Arc<Mutex<Thing>>,
}

impl SharedThing {
    pub fn init_and_run(address: String, db_path: String) -> Result<Self, Error> {
        let db = LmdbEventDatabase::new(Path::new(&db_path)).unwrap();
        let pack = Thing::new(db, IdentifierPrefix::default());
        let shared_pack = Arc::new(Mutex::new(pack));
        let locaked_pack = Arc::clone(&shared_pack);
        thread::spawn(move || {
            run(&address, locaked_pack).unwrap();
        });
        Ok(SharedThing { thing: shared_pack })
    }

    pub fn get_datum_list(&self) -> Result<String, Error> {
        let locked_pack = self.thing.lock().unwrap();
        locked_pack.get_datum_list()
    }

    pub fn get_state(&self) -> Result<Option<IdentifierState>, Error> {
        let locked_pack = self.thing.lock().unwrap();
        locked_pack.get_state()
    }

    pub fn get_formatted_kerl(&self) -> Result<String, Error> {
        let locked_pack = self.thing.lock().unwrap();
        let kerl = locked_pack.get_kerl()?.unwrap();
        Ok(TCPCommunication::format_event_stream(&kerl, false))
    }
}

pub fn run(address: &str, controller: Arc<Mutex<Thing>>) -> Result<(), Error> {
    let listener = TcpListener::bind(&address)?;

    loop {
        let (mut socket, _adr) = listener.accept()?;
        &socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        &socket.set_write_timeout(Some(Duration::from_millis(200)))?;

        loop {
            let msg: Vec<u8> = TCPCommunication::read_all(&socket)?;
            if msg.len() == 0 {
                break;
            }
            let msg = &msg;
            if msg.len() > 0 {
                let ad: Result<SignedAttestationDatum, Error> =
                    serde_json::from_str(&String::from_utf8(msg.to_vec()).unwrap())
                        .map_err(|e| Error::Generic(e.to_string()));
                match ad {
                    Ok(a) => {
                        let mut thing = controller.lock().unwrap();

                        let v = a.get_attestation_datum()?.as_bytes().to_vec();
                        println!(
                            "Added document:\ndocument hash: {}\ndocument: \n{}\n",
                            base64::encode_config(blake3::hash(&v).as_bytes().to_vec(), base64::URL_SAFE),
                            serde_json::to_string_pretty(&a).unwrap()
                        );
                        thing.add_document(a)?;
                    }
                    Err(_) => {
                        let (event, signature) =
                            match signed_event_stream(msg).unwrap().1[0].clone() {
                                keri::event_message::parse::Deserialized::Event(ev) => {
                                    println!("Got event");
                                    // println!("Got event: \n{}", serde_json::to_string_pretty(&ev.event.event).unwrap());
                                    (ev.event.event, ev.signatures[0].signature.signature.clone())
                                }
                                _ => {
                                    return Err(Error::Generic("Wrong event type".into()));
                                }
                            };
                        {
                            let mut thing = controller.lock().unwrap();
                            thing.process(event, signature)?;
                            println!(
                                "Current pack's kerl: \n{}",
                                TCPCommunication::format_event_stream(
                                    &thing.get_kerl()?.unwrap(),
                                    false
                                )
                            )
                        }
                    }
                }
                socket.write_all("ok".as_bytes())?;
            }
        }
        println!("==========================================================");
    }
}

pub fn send(msg: &[u8], address: &str) -> Result<Vec<u8>, Error> {
    let mut stream = TcpStream::connect(address)?;
    stream.write_all(&msg)?;
    let mut buf = [0; 2048];
    let n = stream.read(&mut buf)?;

    Ok(buf[..n].to_vec())
}

use std::io;
pub fn get_input(prompt: &str) -> String {
    println!("{}", prompt);
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_goes_into_input_above) => {}
        Err(_no_updates_is_fine) => {}
    }
    input.trim().to_string()
}

#[derive(Clone)]
pub struct Pack {
    address: String,
    state: IdentifierState,
    attestations: Vec<AttestationDatum>

}

impl Pack {

    pub fn new(address: String) -> Self {
        Pack {address: address, state: IdentifierState::default(), attestations: vec![]}
    }

    pub fn incept_thing(
        &mut self,
        sender: &mut SharedController,
        courier: &SharedController,
        receiver: &SharedController,
    ) -> Result<(), Error> {
        let pk = Key::new(sender.get_current_pk(), KeyType::Ed25519Sha512);
        let next_pk = Key::new(courier.get_current_pk(), KeyType::Ed25519Sha512);

        let icp_msg = make_icp(&pk, &next_pk, None)?;
        let signature = sender.sign(&String::from_utf8(icp_msg.serialize()?).unwrap())?;
        let signed_icp = icp_msg.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )]);

        let mut pack_state = signed_icp.apply_to(self.state.clone())?;

        // Send icp event.
        let msg = signed_icp.serialize().unwrap();
        send(&msg, &self.address)?;

        let comment = &format!(
                "Pack posted from {} to {}",
                &sender.get_prefix()?,
                &receiver.get_prefix()?
            );
        // Send document that confirm package sending
        // let post_receipt = AttestationDatum::new(
        //     comment,
        //     &sender.get_prefix()?,
        // );
        let ad = AttestationDatum::new(comment, &sender.get_prefix()?, vec![]);
        let signed_post_receipt = sender.issue_vc(&serde_json::to_string(&ad).unwrap())?;
        self.attestations.push(ad);

        let vc_str = signed_post_receipt.get_attestation_datum()?.clone();
        let ixn = event_generator::make_ixn(Some(&vc_str), pack_state.clone())?;
        let signature = sender.sign(std::str::from_utf8(&ixn.serialize()?).unwrap())?;
        let signed_ixn = ixn.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )]);

        pack_state = signed_ixn.apply_to(pack_state)?;

        // Sender attach confirmation of sending to pack kel.
        let msg = signed_ixn.serialize().unwrap();
        send(&msg, &self.address)?;

        let mmm = signed_post_receipt.serialize()?.as_bytes().to_vec();
        send(&mmm, &self.address)?;

        let receipt_hash = base64::encode_config(
            blake3::hash(signed_post_receipt.get_attestation_datum()?.as_bytes())
                .as_bytes()
                .to_vec(),
            base64::URL_SAFE,
        );
        println!(
            "{}\nConformation document hash: {}",
            comment,
            receipt_hash
        );

        self.state = pack_state.clone();
        Ok(())
    }

    pub fn transfer_ownership(
        &mut self,
        owner: &mut SharedController,
        next_owner: &SharedController,
        comment: &str
    ) -> Result<(), Error> {
        let pk = Key::new(owner.get_current_pk(), KeyType::Ed25519Sha512);
        let next_pk = Key::new(next_owner.get_current_pk(), KeyType::Ed25519Sha512);

        let rot_msg = event_generator::make_rot(&pk, &next_pk, self.state.clone())?;
        let signature = owner.sign(&String::from_utf8(rot_msg.serialize()?).unwrap())?;
        let signed_rot = rot_msg.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )]);

        let mut pack_state = signed_rot.apply_to(self.state.clone())?;

        // Send the rotation event.
        let msg = signed_rot.serialize().unwrap();
        send(&msg, &self.address)?;

        // Send document that confirm package sending
        // let post_receipt = AttestationDatum::new(
        //     comment,
        //     &owner.get_prefix()?,
        // );

        let last_ad = self.attestations.last().unwrap().to_owned();
        let ad = AttestationDatum::new(&comment, &owner.get_prefix()?, vec![last_ad.get_id()]);
        let signed_post_receipt = owner.issue_vc(&serde_json::to_string(&ad).unwrap())?;
        self.attestations.push(ad);

        let vc_str = signed_post_receipt.get_attestation_datum()?.clone();
        let ixn = event_generator::make_ixn(Some(&vc_str), pack_state.clone())?;
        let signature = owner.sign(std::str::from_utf8(&ixn.serialize()?).unwrap())?;
        let signed_ixn = ixn.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )]);

        pack_state = signed_ixn.apply_to(pack_state)?;

        // Sender attach confirmation of sending to pack kel.
        let msg = signed_ixn.serialize().unwrap();
        send(&msg, &self.address)?;

        let mmm = signed_post_receipt.serialize()?.as_bytes().to_vec();
        send(&mmm, &self.address)?;

        let receipt_hash = base64::encode_config(
            blake3::hash(signed_post_receipt.get_attestation_datum()?.as_bytes())
                .as_bytes()
                .to_vec(),
            base64::URL_SAFE,
        );
        println!(
            "{}\nConformation document hash: {}",
            comment,
            receipt_hash
        );
        self.state = pack_state.clone();

        Ok(())
    }

    pub fn receive(&mut self, receiver: SharedController, comment: &str) -> Result<(), Error> {
        let pk = Key::new(receiver.get_current_pk(), KeyType::Ed25519Sha512);
        let next_pk = Key::new(receiver.get_next_pk(), KeyType::Ed25519Sha512);

        let rot_msg = event_generator::make_rot(&pk, &next_pk, self.state.clone())?;
        let signature = receiver.sign(&String::from_utf8(rot_msg.serialize()?).unwrap())?;
        let signed_rot = rot_msg.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )]);

        let mut pack_state = signed_rot.apply_to(self.state.clone())?;

        // Send the rotation event.
        let msg = signed_rot.serialize().unwrap();
        send(&msg, &self.address)?;

        // Send document that confirm package sending
        // let post_receipt = AttestationDatum::new(
        //     comment,
        //     &owner.get_prefix()?,
        // );
        let last_ad = self.attestations.last().unwrap().to_owned();
        let ad = AttestationDatum::new(comment, &receiver.get_prefix()?, vec![last_ad.get_id()]);
        let signed_post_receipt = receiver.issue_vc(&serde_json::to_string(&ad).unwrap())?;

        let vc_str = signed_post_receipt.get_attestation_datum()?.clone();
        let ixn = event_generator::make_ixn(Some(&vc_str), pack_state.clone())?;
        let signature = receiver.sign(std::str::from_utf8(&ixn.serialize()?).unwrap())?;
        let signed_ixn = ixn.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )]);

        pack_state = signed_ixn.apply_to(pack_state)?;

        // Sender attach confirmation of sending to pack kel.
        let msg = signed_ixn.serialize().unwrap();
        send(&msg, &self.address)?;

        let mmm = signed_post_receipt.serialize()?.as_bytes().to_vec();
        send(&mmm, &self.address)?;

        let receipt_hash = base64::encode_config(
            blake3::hash(signed_post_receipt.get_attestation_datum()?.as_bytes())
                .as_bytes()
                .to_vec(),
            base64::URL_SAFE,
        );
        println!(
            "{}\nConformation document hash: {}",
            comment,
            receipt_hash
        );
        self.state = pack_state.clone();

        Ok(())
    }
}

#[test]
pub fn test() -> Result<(), Error> {
    use crate::controller::Controller;
    use tempfile::tempdir;

    let db_dir = tempdir()?;
    let adr_store_path = [db_dir.path().to_str().unwrap(), "adr"].join("");

    // Setup empty pack kerl
    let mut pack = Pack::new("localhost:1111".to_string());

    // Setup actors controller
    let sender_db_dir = tempdir().unwrap();
    let sender_db_path = sender_db_dir.path().to_str().unwrap();
    let mut sender = Controller::new(sender_db_path, "localhost:1212", &adr_store_path);
    sender.update_keys()?;
    println!(
        "Sender: {}, current key: {}\n",
        sender.get_prefix()?,
        base64::encode_config(&sender.get_current_pk(), base64::URL_SAFE)
    );

    // Setup receiver controller
    let receiver_db_dir = tempdir().unwrap();
    let receiver_db_path = receiver_db_dir.path().to_str().unwrap();
    let receiver = Controller::new(receiver_db_path, "localhost:1212", &adr_store_path);
    println!(
        "Receiver: {}, current key: {}\n",
        receiver.get_prefix()?,
        base64::encode_config(&receiver.get_current_pk(), base64::URL_SAFE)
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

    get_input("Press enter to continue...");
    println!("Sender fills the sending form\n");
    // ========================================================
    // Sender fills the sending form
    // Incept pack kel with sender key as current key and courier public key as next.
    // Insert to pack kel interaction event with document hash.
    // ========================================================
    // pack.incept_thing(
    //     &mut sender,
    //     &courier,
    //     &receiver,
    // )?;

    get_input("Press enter to continue...");
    println!("Courier got the package\n");
    // ========================================================
    // Courier got the package from Sender
    // Rotate pack kel with courier key as current key and storage public key as next.
    // Insert to pack kel interaction event with document hash.
    // ========================================================
    // pack.transfer_ownership(&mut courier, &receiver, &format!("Got pack from {}", &sender.get_prefix()?))?;

    Ok(())
}
