use crate::{
    address_provider::AddressProvider, controller::Controller, entity::Entity, error::Error,
};
use keri::{event_message::parse, prefix::Prefix};
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
        let mut stream =
            TcpStream::connect(address.clone()).map_err(|e| Error::CommunicationError(e))?;
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(|e| Error::CommunicationError(e))?;
        stream
            .write(&msg)
            .map_err(|e| Error::CommunicationError(e))?;
        // println!("Sent:\n{}\n", from_utf8(message).unwrap());
        let mut buf = [0; 2048];
        let n = stream
            .read(&mut buf)
            .map_err(|e| Error::CommunicationError(e))?;

        println!("{}", TCPCommunication::format_event_stream(&buf[..n], true));

        let res = entity.respond(&buf[..n])?;

        if res.len() != 0 {
            let mut msg = [to_who, " "].join("").as_bytes().to_vec();
            msg.extend(res);

            stream
                .write(&msg)
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

    pub fn run(address: String, controller: Arc<Mutex<Controller>>) -> Result<(), Error> {
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
                    let k = controller.lock().unwrap();

                    let receipt = k.parse_message(msg).expect("failed while event processing");

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

    pub fn get_address(&self) -> String {
        self.address.clone()
    }
}
