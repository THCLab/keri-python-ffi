use crate::{
    address_provider::AddressProvider, controller::Controller, entity::Entity, error::Error,
};
use keri::{event_message::parse, prefix::Prefix};
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
        stream.write(&msg)?;
        let mut buf = [0; 2048];

        let n = stream.read(&mut buf)?;

        println!("{}", TCPCommunication::format_event_stream(&buf[..n], true));
        let res = entity.respond(&buf[..n])?;

        if res.len() != 0 {
            let mut msg = [to_who, " "].join("").as_bytes().to_vec();
            msg.extend(res);

            stream.write(&msg)?;
        }
        Ok(())
    }

    pub fn ask_for_tel(vc: &[u8], address: &str) -> Result<Vec<u8>, Error> {
        let mut msg = "tel ".as_bytes().to_vec();
        msg.extend(vc);
        let mut stream = TcpStream::connect(address.clone())?;
        stream.write_all(&msg)?;
        // println!("Sent:\n{}\n", from_utf8(&msg).unwrap());
        let mut buf = [0; 2048];
        let n = stream.read(&mut buf)?;
        let m = buf[..n].to_vec().clone();

        Ok(m)
    }

    pub fn run(address: String, controller: Arc<Mutex<Controller>>) -> Result<(), Error> {
        let listener = TcpListener::bind(&address)?;
        println!("Listening on: {}", address);

        loop {
            let (mut socket, _adr) = listener.accept()?;
            socket.set_read_timeout(Some(Duration::from_millis(200)))?;
            socket.set_write_timeout(Some(Duration::from_millis(200)))?;

            let c = Arc::clone(&controller);

            let mut buf = vec![0; 2048];
            loop {
                let n = socket.read(&mut buf)?;

                if n == 0 {
                    break;
                }

                let msg = &buf[..n];
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
