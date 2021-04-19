use crate::{
    communication::address_provider::AddressProvider, controller::entity::Entity,
    controller::Controller, error::Error,
};
use base64::URL_SAFE;
use keri::{
    event::event_data::EventData,
    event::sections::seal::Seal,
    event_message::parse::{signed_event_stream, Deserialized},
    prefix::Prefix,
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    time::Duration,
};

pub struct TCPCommunication {
    address: String,
    address_provider: AddressProvider,
}

impl TCPCommunication {
    pub fn new(adr: &str, ap_path: &str) -> Result<Self, Error> {
        let ap = AddressProvider::new(ap_path)?;
        Ok(TCPCommunication {
            address: adr.to_string(),
            address_provider: ap,
        })
    }

    pub fn register(&self, pref: &str) -> Result<(), Error> {
        self.address_provider.register(pref, &self.address)
    }

    pub fn get_address_for_prefix(&self, prefix: &str) -> Result<Option<String>, Error> {
        self.address_provider.get_address(prefix)
    }

    pub fn send(message: &[u8], address: &str, to_who: &str, entity: &Entity) -> Result<(), Error> {
        let mut msg = [to_who, " "].join("").as_bytes().to_vec();
        msg.extend(message);
        let mut stream = TcpStream::connect(address.clone())?;
        stream.set_read_timeout(Some(Duration::from_millis(500)))?;
        stream.write_all(&msg)?;

        let msg = TCPCommunication::read_all(&stream)?;

        println!("{}", TCPCommunication::format_event_stream(&msg, true));
        let res = entity.respond(&msg)?;

        if res.len() != 0 {
            let mut msg = [to_who, " "].join("").as_bytes().to_vec();
            msg.extend(res);

            stream.write_all(&msg)?;
        }
        Ok(())
    }

    pub fn ask_for_tel(vc: &[u8], address: &str) -> Result<Vec<u8>, Error> {
        let mut msg = "tel ".as_bytes().to_vec();
        msg.extend(vc);
        let mut stream = TcpStream::connect(address.clone())?;
        stream.write_all(&msg)?;
        // println!("Sent:\n{}\n", String::from_utf8(msg).unwrap());
        let mut buf = [0; 2048];
        let n = stream.read(&mut buf)?;
        let m = buf[..n].to_vec().clone();

        Ok(m)
    }

    pub fn run(address: String, controller: Arc<Mutex<Controller>>) -> Result<(), Error> {
        let listener = TcpListener::bind(&address)?;
        // println!("Listening on: {}", address);

        loop {
            let (mut socket, _adr) = listener.accept()?;
            &socket.set_read_timeout(Some(Duration::from_millis(200)))?;
            &socket.set_write_timeout(Some(Duration::from_millis(200)))?;

            let c = Arc::clone(&controller);

            loop {
                let msg: Vec<u8> = TCPCommunication::read_all(&socket)?;

                if msg.len() == 0 {
                    break;
                }
                let msg = &msg;
                if msg.len() > 0 {
                    let k = c.lock().unwrap();
                    let receipt = k.parse_message(msg).expect("failed while event processing");

                    socket.write_all(&receipt)?;
                }
            }
        }
    }

    pub fn format_event_stream(msg: &[u8], incoming: bool) -> String {
        let mut out = String::new();
        let s = signed_event_stream(msg).unwrap().1;
        for ev in s {
            match ev {
                Deserialized::Event(e) => {
                    let t = match e.event.event.event.event_data {
                        EventData::Icp(icp) => {
                            if incoming {
                                out.push_str(
                                    &[
                                        "\nPairing with ",
                                        &e.event.event.event.prefix.to_str(),
                                        "\n",
                                    ]
                                    .join(""),
                                );
                            }
                            [
                                "inception, current key:",
                                &icp.key_config
                                    .public_keys
                                    .iter()
                                    .map(|k| k.to_str())
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            ]
                            .join(" ")
                        }
                        EventData::Rot(e) => [
                            "rotation, current key:",
                            &e.key_config
                                .public_keys
                                .iter()
                                .map(|k| k.to_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                        ]
                        .join(" "),
                        EventData::Ixn(ixn) => {
                            let digest = match ixn.data[0] {
                                Seal::Event(ref es) => {
                                    base64::encode_config(&es.event_digest.digest, URL_SAFE)
                                }
                                Seal::Location(_) => "".into(),
                                Seal::Digest(ref d) => {
                                    base64::encode_config(&d.dig.digest, URL_SAFE)
                                }
                                Seal::Root(_) => "".into(),
                            };
                            ["interaction,".to_string(), "digest:".to_string(), digest].join(" ")
                        }
                        _ => "".to_string(),
                    };
                    out.push_str(&format!("\tsn: {}, type: {}\n", e.event.event.event.sn, t));
                }
                Deserialized::Vrc(_) => {
                    // println!("\ttype: {}", "receipt");
                }
                Deserialized::Rct(_) => {}
            }
        }
        out
    }
    pub fn read_all(mut stream: &TcpStream) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0; 2048];
        let mut msg: Vec<u8> = vec![];
        match stream.read(&mut buf) {
            Ok(m) => {
                msg.extend(&buf[..m].to_vec());
                let mut m = m;
                while m == buf.len() {
                    m = stream.read(&mut buf)?;

                    msg.extend(&buf[..m].to_vec());
                }
            }
            Err(e) => return Err(Error::CommunicationError(e)),
        };

        Ok(msg)
    }

    pub fn get_address(&self) -> String {
        self.address.clone()
    }
}
