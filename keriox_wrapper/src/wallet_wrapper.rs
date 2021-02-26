use jolocom_native_utils::wallet::wallet::Wallet;
use keri::{error::Error, signer::KeyManager};

pub struct WalletWrapper {
    wallet: Wallet,
}

impl KeyManager for WalletWrapper {
    fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error> {
        self.wallet
            .sign(msg)
            .map_err(|e| Error::SemanticError(e.to_string()))
    }

    fn public_key(&self) -> ursa::keys::PublicKey {
        self.wallet.public_key()
    }

    fn next_public_key(&self) -> ursa::keys::PublicKey {
        self.wallet.next_public_key()
    }

    fn rotate(&mut self) -> Result<(), keri::error::Error> {
        self.wallet
            .rotate()
            .map_err(|e| Error::SemanticError(e.to_string()))
    }
}

impl WalletWrapper {
    pub fn new() -> Self {
        WalletWrapper {
            wallet: Wallet::new(),
        }
    }

    pub fn incept_wallet_from_seed(&mut self, seeds: Vec<&str>) -> Result<(String, String), Error> {
        self.wallet
            .incept_wallet_from_seed(seeds)
            .map_err(|e| Error::SemanticError(e.to_string()))
    }
}
