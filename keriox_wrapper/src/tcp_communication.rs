use crate::{
    address_provider::AddressProvider, entity::Entity, error::Error, wallet_wrapper::WalletWrapper,
};
use keri::{
    database::lmdb::LmdbEventDatabase,
    event_message::parse,
    keri::Keri,
    prefix::{IdentifierPrefix, Prefix},
    state::IdentifierState,
};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    time::Duration,
};

pub struct TCPCommunication {
    address: String,
    address_provider: AddressProvider,
}

impl TCPCommunication {
    pub fn new(pref: &str, adr: &str, ap_path: &str) -> Result<Self, Error> {
        let ap = AddressProvider::new(ap_path)?;
        ap.register(pref, adr)?;
        Ok(TCPCommunication {
            address: adr.to_string(),
            address_provider: ap,
        })
    }

    fn send(
        message: &[u8],
        address: &str,
        keri: &Keri<LmdbEventDatabase, WalletWrapper>,
    ) -> Result<(), Error> {
        let mut stream =
            TcpStream::connect(address.clone()).map_err(|e| Error::CommunicationError(e))?;
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(|e| Error::CommunicationError(e))?;
        stream
            .write(message)
            .map_err(|e| Error::CommunicationError(e))?;
        // println!("Sent:\n{}\n", from_utf8(message).unwrap());
        let mut buf = [0; 2048];
        let n = stream
            .read(&mut buf)
            .map_err(|e| Error::CommunicationError(e))?;

        println!(
            "{}",
            TCPCommunication::format_event_stream(&buf[..n], true)
        );

        let res = keri.respond(&buf[..n])?;

        if res.len() != 0 {
            stream
                .write(&res)
                .map_err(|e| Error::CommunicationError(e))?;
            // println!("Sent: {}", String::from_utf8(res.clone()).unwrap());

            match stream.read(&mut buf) {
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock => {
                        // println!("would have blocked");
                    }
                    _ => panic!("Got an error: {}", e),
                },
                Ok(_) => {
                    // println!("Got:\n{}\n", from_utf8(&buf[..m]).unwrap());
                }
            };
        }
        Ok(())
    }

    pub fn run(address: String, ent: Arc<Mutex<Entity>>) -> Result<(), Error> {
        let listener = TcpListener::bind(&address).map_err(|e| Error::CommunicationError(e))?;
        println!("Listening on: {}", address);

        loop {
            let (mut socket, _) = listener
                .accept()
                .map_err(|e| Error::CommunicationError(e))?;
            socket
                .set_read_timeout(Some(Duration::from_millis(200)))
                .map_err(|e| Error::CommunicationError(e))?;
            socket
                .set_write_timeout(Some(Duration::from_millis(200)))
                .map_err(|e| Error::CommunicationError(e))?;
            let mut buf = [0; 2048];

            loop {
                let n = match socket.read(&mut buf) {
                    Err(e) => match e.kind() {
                        io::ErrorKind::WouldBlock => {
                            // println!("would have blocked");
                            break;
                        }
                        _ => return Err(Error::CommunicationError(e)),
                    },
                    Ok(m) => m,
                };

                let msg = &buf[..n];
                {
                    let k = ent.lock().unwrap();

                    if msg.len() > 0 {
                        println!(
                            "{}",
                            TCPCommunication::format_event_stream(msg, true)
                        );
                    }

                    let receipt = k.respond(msg).expect("failed while event processing");

                    match socket.write_all(&receipt) {
                        Err(e) => match e.kind() {
                            io::ErrorKind::WouldBlock => {
                                // println!("would have blocked");
                                break;
                            }
                            _ => return Err(Error::CommunicationError(e)),
                        },
                        Ok(_) => {}
                    };
                }
            }
        }
    }

    pub fn format_event_stream(msg: &[u8], incoming: bool) -> String {
        let mut out = String::new();
        let s = parse::signed_event_stream(msg).unwrap().1;
        for ev in s {
            match ev {
                parse::Deserialized::Event(e) => {
                    let t = match e.event.event.event.event_data {
                        keri::event::event_data::EventData::Icp(icp) => {
                          if incoming {
                            out.push_str(&["\nPairing with ", &e.event.event.event.prefix.to_str(), "\n"].join(""));
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
                        keri::event::event_data::EventData::Rot(e) => [
                            "rotation, current key:",
                            &e.key_config
                                .public_keys
                                .iter()
                                .map(|k| k.to_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                        ]
                        .join(" "),
                        keri::event::event_data::EventData::Ixn(_) => "interaction".to_string(),
                        _ => "".to_string(),
                    };
                    out.push_str(&format!("\tsn: {}, type: {}\n", e.event.event.event.sn, t));
                }
                parse::Deserialized::Vrc(_) => {
                    // println!("\ttype: {}", "receipt");
                }
                parse::Deserialized::Rct(_) => {}
            }
        }
        out
    }

    pub fn get_state(
        &self,
        id: &IdentifierPrefix,
        keri: &Keri<LmdbEventDatabase, WalletWrapper>,
    ) -> Result<Option<IdentifierState>, Error> {
        match keri.get_state_for_prefix(id)? {
            Some(state) => Ok(Some(state)),
            None => {
                let kerl = keri
                    .get_kerl()?
                    .ok_or(Error::Generic("Can't find kerl".into()))?;
                let addr = self
                    .address_provider
                    .get_address(&id.to_str())?
                    .ok_or(Error::Generic("Can't find address for prefix".into()))?;
                TCPCommunication::send(&kerl, &addr, &keri)?;
                Ok(keri.get_state_for_prefix(id)?)
            }
        }
    }

    pub fn get_address(&self) -> String {
        self.address.clone()
    }
}
