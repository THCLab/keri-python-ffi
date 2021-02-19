use crate::kerl::Kerl;
use crate::{error::Error as kerError};
use keri::{
    prefix::{IdentifierPrefix, Prefix},
    state::IdentifierState,
};
use std::{
    error::Error,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    str::from_utf8,
};

pub struct TalkingKerl {
    kerl: Kerl,
    id: IdentifierPrefix,
}

impl TalkingKerl {
    pub fn new(kerl: Kerl) -> Result<Self, kerError> {
        Ok(TalkingKerl {
            kerl,
            id: IdentifierPrefix::default(),
        })
    }

    fn send(&self, message: &[u8], address: &str) -> Result<(), Box<dyn Error>> {
        let mut stream = TcpStream::connect(address.clone())?;
        stream.write(message)?;
        println!("Sent:\n{}\n", from_utf8(message).unwrap());
        let mut buf = [0; 1024];
        let n = stream.read(&mut buf)?;
        println!("Got:\n{}\n", from_utf8(&buf[..n]).unwrap());

        self.kerl.process_events(&buf[..n])?;
        // let res = self.kerl.get_kerl(&self.kerl.id)?.unwrap();

        // if res.len() != 0 {
        //     stream.write(&res).await?;
        //     println!("Sent: {}", String::from_utf8(res.clone()).unwrap());

        //     let n = match timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
        //         Ok(n) => n?,
        //         Err(_) => 0,
        //     };

        //     println!("Got:\n{}\n", from_utf8(&buf[..n]).unwrap());
        // }

        Ok(())
    }

    pub fn run(&self, prefix: &IdentifierPrefix, address: &str) -> Result<(), Box<dyn Error>> {
        // let keri_instance = Arc::new(Mutex::new(self.kerl));

        let listener = TcpListener::bind(&address.to_string())?;
        println!("Listening on: {}", address);

        loop {
            let (mut socket, _) = listener.accept()?;
            let mut buf = [0; 1024];

            loop {
                let n = socket
                    .read(&mut buf)
                    .expect("failed to read data from socket");

                if n != 0 {
                    let msg = &buf[..n];
                    println!("Got: \n {}\n", String::from_utf8(msg.to_vec()).unwrap());
                    self.kerl
                        .process_events(msg)
                        .expect("failed while event processing");
                    let receipt = self.kerl.get_kerl(prefix).unwrap().unwrap();

                    socket
                        .write_all(&receipt)
                        .expect("failed to write data to socket");
                    println!(
                        "Respond with {}\n",
                        String::from_utf8(receipt.clone()).unwrap()
                    );
                }
            }
        }
    }

    pub fn get_state(
        &self,
        id: &IdentifierPrefix,
        address: &str
    ) -> Result<Option<IdentifierState>, Box<dyn Error>> {
        match self.kerl.get_state(id)? {
            Some(state) => Ok(Some(state)),
            None => {
                // let address = address_provider.get_address(&id.to_str()).unwrap().unwrap();
                println!("id: {}", self.id.to_str());
                let kerl = self.kerl(&self.id)?.unwrap();
                self.send(&kerl, address)?;
                Ok(self.kerl.get_state(id).unwrap())
            }
        }
    }

    pub fn proccess(&self, events: &[u8]) -> Result<(), kerError> {
        self.kerl.process_events(events)?;
        Ok(())
    }

    pub fn set_id(&mut self, id: IdentifierPrefix) {
        self.id = id;
    }

    pub fn kerl(&self, pref: &IdentifierPrefix) -> Result<Option<Vec<u8>>, kerError> {
        self.kerl.get_kerl(pref)
    }
}