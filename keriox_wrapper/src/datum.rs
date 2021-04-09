use std::fmt;

use base64::URL_SAFE;
use serde::{Deserialize, Serialize, Serializer};

use crate::error::Error;
#[derive(Serialize, Deserialize, Clone)]
pub struct Datum {
    pub issuer: String,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
struct Proof {
    signature: String,
}

// AttestationDatumID (ADID) - identifier, which can be designated by Testator
// to uniquely track specific attestation. ADID is always within namespace of
// the Testator Identifier making it always globally unique.
// example: did:123456789/attestationID/d12345
//          ------------                ------
//               |                         |
//            testator did            attestation id
#[derive(Deserialize, Clone)]
pub struct AttestationDatumId {
    testator_id: String,
    attestation_id: String,
}

impl AttestationDatumId {
    pub fn new(testator_id: &str, attestation_id: &str) -> Self {
        AttestationDatumId {
            testator_id: testator_id.into(),
            attestation_id: attestation_id.into(),
        }
    }
}

impl Serialize for AttestationDatumId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl fmt::Display for AttestationDatumId {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let str = [
            "did:keri:",
            &self.testator_id,
            "/attestationId/",
            &self.attestation_id,
        ]
        .join("");
        write!(fmt, "{}", str)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AttestationDatum {
    #[serde(rename = "AttestationDatumId")]
    id: AttestationDatumId,
    #[serde(rename = "AttestedDatumSources")]
    source: Vec<AttestationDatumId>,
    #[serde(rename = "Datum")]
    datum: Datum,
}

impl AttestationDatum {
    pub fn attach_signature(&self, signature: Vec<u8>) -> Result<SignedAttestationDatum, Error> {
        let b64_signature = base64::encode_config(signature, URL_SAFE);
        let proof = Proof {
            signature: b64_signature,
        };
        Ok(SignedAttestationDatum {
            at_datum: self.clone(),
            proof,
        })
    }

    pub fn new(msg: &str, issuer: &str) -> Self {
        let datum = Datum {
            message: msg.into(),
            issuer: issuer.into(),
        };
        let b64_hash = base64::encode_config(
            blake3::hash(&serde_json::to_vec(&datum).unwrap()).as_bytes(),
            URL_SAFE,
        );
        let id = AttestationDatumId::new(issuer, &b64_hash);
        let source = vec![AttestationDatumId::new(issuer, "sourceID")];
        AttestationDatum { id, source, datum }
    }

    pub fn get_datum(&self) -> Datum {
        self.datum.clone()
    }
}

#[derive(Serialize, Deserialize)]
pub struct SignedAttestationDatum {
    #[serde(flatten)]
    at_datum: AttestationDatum,
    proof: Proof,
}

impl SignedAttestationDatum {
    pub fn get_signature(&self) -> Result<Vec<u8>, Error> {
        base64::decode_config(self.proof.signature.clone(), URL_SAFE)
            .map_err(|e| Error::Decode64Error(e))
    }

    pub fn get_datum(&self) -> Datum {
        self.at_datum.get_datum()
    }

    pub fn get_attestation_datum(&self) -> Result<String, Error> {
        serde_json::to_string(&self.at_datum).map_err(|_| Error::Generic("serde error".into()))
    }
}

#[test]
pub fn test_attestation() -> Result<(), Error> {
    let issuer_str = "D5bw5KrpU2xRc3Oi4rsyBK9By6aotmXU0fNEybJbja1Q";
    let msg_str = "hi there";
    let ad = AttestationDatum::new(msg_str, issuer_str);

    println!("{}", serde_json::to_string_pretty(&ad).unwrap());
    Ok(())
}
