use jolocom_native_utils::wallet::wallet::Wallet;
use jolocom_native_utils::{
    did_document::{VerificationMethod, VerificationMethodProperties},
    wallet::wallet::ExportedWallet,
};
use keri::{error::Error, signer::KeyManager};
pub struct WalletWrapper {
    wallet: Wallet,
}

impl KeyManager for WalletWrapper {
    fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error> {
        self.wallet.sign(msg).map_err(|e| {
            Error::SemanticError(["error while signing: ".to_string(), e.to_string()].join(""))
        })
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

    pub fn incept_wallet() -> Result<WalletWrapper, Error> {
        let wallet = Wallet::incept_wallet().map_err(|e| Error::SemanticError(e.to_string()))?;
        Ok(WalletWrapper { wallet })
    }

    pub fn incept_wallet_from_seed(seeds: Vec<&str>) -> Result<WalletWrapper, Error> {
        let wallet = Wallet::incept_wallet_from_seed(seeds)
            .map_err(|e| Error::SemanticError(e.to_string()))?;
        Ok(WalletWrapper { wallet })
    }

    pub fn verify(&self, msg: &Vec<u8>, signature: &[u8]) -> Result<bool, Error> {
        self.wallet.verify(msg, signature).map_err(|e| {
            Error::SemanticError(["error while verify: ".to_string(), e.to_string()].join(""))
        })
    }

    pub fn verify_with_key(
        &self,
        vm: &VerificationMethod,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error> {
        let key_b64_str = match &vm.key {
            VerificationMethodProperties::EthereumAddress(k) => k,
            VerificationMethodProperties::Base16(k) => k,
            VerificationMethodProperties::Base58(k) => k,
            VerificationMethodProperties::Base64(k) => k,
            VerificationMethodProperties::Jwk(k) => k,
            VerificationMethodProperties::Pem(k) => k,
        };

        Ok(
            Wallet::verify_with_key(key_b64_str, &vm.key_type.to_string(), data, signature)
                .map_err(|e| Error::SemanticError(e.to_string()))?,
        )
    }

    pub fn new_encrypted_wallet(pass: &str) -> Result<ExportedWallet, Error> {
        ExportedWallet::incepted_enc_wallet(pass).map_err(|e| Error::SemanticError(e.to_string()))
    }

    pub fn to_wallet(enc_wallet: ExportedWallet, pass: &str) -> Result<WalletWrapper, Error> {
        Ok(WalletWrapper {
            wallet: enc_wallet
                .to_wallet(pass)
                .map_err(|e| Error::SemanticError(e.to_string()))?,
        })
    }
}
