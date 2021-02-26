use crate::{
    address_provider::AddressProvider, wallet_wrapper::WalletWrapper,
};
use keri::{
    database::lmdb::LmdbEventDatabase,
    keri::Keri,
    prefix::{IdentifierPrefix, Prefix},
    state::IdentifierState,
};
use std::{
    error::Error,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};

pub struct TalkingKerl {
    address: String,
    address_provider: AddressProvider,
}

impl TalkingKerl {
    pub fn new(pref: &str, adr: &str, ap_path: &str) -> Result<Self, Box<dyn Error>> {
        let ap = AddressProvider::new(ap_path);
        ap.register(pref, adr)?;
        Ok(TalkingKerl {
            address: adr.to_string(),
            address_provider: ap,
        })
    }

    fn send(
        &self,
        message: &[u8],
        address: &str,
        keri: &Keri<LmdbEventDatabase, WalletWrapper>,
    ) -> Result<(), Box<dyn Error>> {
        let mut stream = TcpStream::connect(address.clone())?;
        stream.set_read_timeout(Some(Duration::from_millis(500)))?;
        stream.write(message)?;
        // println!("Sent:\n{}\n", from_utf8(message).unwrap());
        let mut buf = [0; 2048];
        let n = stream.read(&mut buf)?;
        // println!("Got:\n{}\n", from_utf8(&buf[..n]).unwrap());

        let res = keri.respond(&buf[..n])?;

        if res.len() != 0 {
            stream.write(&res)?;
            // println!("Sent: {}", String::from_utf8(res.clone()).unwrap());

            match stream.read(&mut buf) {
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock => {
                        println!("would have blocked");
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

    pub fn run(
        &self,
        address: &str,
        keri: &Keri<LmdbEventDatabase, WalletWrapper>,
    ) -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind(&address.to_string())?;
        println!("Listening on: {}", address);

        loop {
            let (mut socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(Duration::from_millis(200)))?;
            socket.set_write_timeout(Some(Duration::from_millis(200)))?;
            let mut buf = [0; 2048];

            loop {
                let n = match socket.read(&mut buf) {
                    Err(e) => match e.kind() {
                        io::ErrorKind::WouldBlock => {
                            println!("would have blocked");
                            break;
                        }
                        _ => panic!("Got an error: {}", e),
                    },
                    Ok(m) => m,
                };

                let msg = &buf[..n];
                println!("Got: \n {}\n", String::from_utf8(msg.to_vec()).unwrap());
                let receipt = keri.respond(msg).expect("failed while event processing");

                match socket.write_all(&receipt) {
                    Err(e) => match e.kind() {
                        io::ErrorKind::WouldBlock => {
                            println!("would have blocked");
                            break;
                        }
                        _ => panic!("Got an error: {}", e),
                    },
                    Ok(_) => {}
                };
                println!(
                    "Respond with {}\n",
                    String::from_utf8(receipt.clone()).unwrap()
                );
            }
        }
    }

    pub fn get_state(
        &self,
        id: &IdentifierPrefix,
        keri: &Keri<LmdbEventDatabase, WalletWrapper>,
    ) -> Result<Option<IdentifierState>, Box<dyn Error>> {
        match keri.get_state_for_prefix(id)? {
            Some(state) => Ok(Some(state)),
            None => {
                let kerl = keri.get_kerl()?.unwrap();
                let addr = self.address_provider.get_address(&id.to_str())?.unwrap();
                self.send(&kerl, &addr, &keri)?;
                Ok(keri.get_state_for_prefix(id).unwrap())
            }
        }
    }

    pub fn get_address(&self) -> String {
        self.address.clone()
    }
}
