use keri::{
    derivation::basic::Basic,
    prefix::{BasicPrefix, IdentifierPrefix, Prefix},
    state::IdentifierState,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct DIDDocument {
    #[serde(rename = "@context")]
    pub context: String,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_methods: Vec<VerificationMethod>,
}

pub fn state_to_did_document(state: IdentifierState, method_prefix: &str) -> DIDDocument {
    DIDDocument {
        context: "https://www.w3.org/ns/did/v1".to_string(),
        id: ["did", method_prefix, &state.prefix.to_str()].join(":"),
        verification_methods: match state
            .current
            .public_keys
            .iter()
            .map(|pref| pref_to_vm(pref, &state.prefix, method_prefix))
            .collect::<Result<Vec<VerificationMethod>, String>>()
        {
            Ok(vms) => vms,
            // TODO not clean
            Err(_) => vec![],
        },
    }
}

fn pref_to_vm(
    pref: &BasicPrefix,
    controller: &IdentifierPrefix,
    method_prefix: &str,
) -> Result<VerificationMethod, String> {
    Ok(VerificationMethod {
        id: ["#".to_string(), pref.to_str()].join(""),
        key_type: match pref.derivation {
            Basic::Ed25519NT | Basic::Ed25519 => KeyTypes::Ed25519VerificationKey2018,
            Basic::ECDSAsecp256k1NT | Basic::ECDSAsecp256k1 => {
                KeyTypes::EcdsaSecp256k1VerificationKey2019
            }
            Basic::X25519 => KeyTypes::X25519KeyAgreementKey2019,
            _ => return Err("bad key type".to_string()),
        },
        controller: ["did", method_prefix, &controller.to_str()].join(":"),
        key: VerificationMethodProperties::Base64(base64::encode_config(
            pref.derivative(),
            base64::URL_SAFE,
        )),
    })
}

#[derive(Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,

    #[serde(rename = "type")]
    pub key_type: KeyTypes,
    pub controller: String,

    #[serde(flatten)]
    pub key: VerificationMethodProperties,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum KeyTypes {
    JwsVerificationKey2020,
    EcdsaSecp256k1VerificationKey2019,
    Ed25519VerificationKey2018,
    GpgVerificationKey2020,
    RsaVerificationKey2018,
    X25519KeyAgreementKey2019,
    SchnorrSecp256k1VerificationKey2019,
    EcdsaSecp256k1RecoveryMethod2020,
}

#[derive(Serialize, Deserialize)]
pub enum VerificationMethodProperties {
    #[serde(rename = "ethereumAddress")]
    EthereumAddress(String),
    #[serde(rename = "publicKeyHex")]
    Base16(String),
    #[serde(rename = "publicKeyBase58")]
    Base58(String),
    #[serde(rename = "publicKeyBase64")]
    Base64(String),
    #[serde(rename = "publicKeyJwk")]
    Jwk(String),
    #[serde(rename = "publicKeyPem")]
    Pem(String),
}
