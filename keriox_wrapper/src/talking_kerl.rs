use crate::{address_provider::AddressProvider, error::Error, wallet_wrapper::WalletWrapper};
use keri::{
    database::lmdb::LmdbEventDatabase,
    keri::Keri,
    prefix::{IdentifierPrefix, Prefix},
    state::IdentifierState,
};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};

pub struct TalkingKerl {
    address: String,
    address_provider: AddressProvider,
}

impl TalkingKerl {
    pub fn new(pref: &str, adr: &str, ap_path: &str) -> Result<Self, Error> {
        let ap = AddressProvider::new(ap_path)?;
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
        // println!("Got:\n{}\n", from_utf8(&buf[..n]).unwrap());

        let res = keri.respond(&buf[..n])?;

        if res.len() != 0 {
            stream
                .write(&res)
                .map_err(|e| Error::CommunicationError(e))?;
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
    ) -> Result<(), Error> {
        let listener =
            TcpListener::bind(&address.to_string()).map_err(|e| Error::CommunicationError(e))?;
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
                            println!("would have blocked");
                            break;
                        }
                        _ => return Err(Error::CommunicationError(e)),
                    },
                    Ok(m) => m,
                };

                let msg = &buf[..n];
                println!(
                    "Got: \n {}\n",
                    String::from_utf8(msg.to_vec()).map_err(|e| Error::StringFromUtf8Error(e))?
                );
                let receipt = keri.respond(msg).expect("failed while event processing");

                match socket.write_all(&receipt) {
                    Err(e) => match e.kind() {
                        io::ErrorKind::WouldBlock => {
                            println!("would have blocked");
                            break;
                        }
                        _ => return Err(Error::CommunicationError(e)),
                    },
                    Ok(_) => {}
                };
                println!(
                    "Respond with {}\n",
                    String::from_utf8(receipt.clone())
                        .map_err(|e| Error::StringFromUtf8Error(e))?
                );
            }
        }
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
                self.send(&kerl, &addr, &keri)?;
                Ok(keri.get_state_for_prefix(id)?)
            }
        }
    }

    pub fn get_address(&self) -> String {
        self.address.clone()
    }
}
