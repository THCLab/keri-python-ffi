use std::{fmt, str::FromStr};

use base64::URL_SAFE;
use serde::{de, Deserialize, Serialize, Serializer};

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
#[derive(Clone)]
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

impl<'de> Deserialize<'de> for AttestationDatumId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
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

impl FromStr for AttestationDatumId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.replace("\"", "");
        let splietted_data: Vec<&str> = s.split(':').collect();
        let data = splietted_data
            .get(2)
            .ok_or(Error::Generic("Inpropper datum id format".into()))?;
        let splitted: Vec<&str> = data.split("/").collect();
        let testator_id = splitted
            .get(0)
            .ok_or(Error::Generic("Inpropper datum id format".into()))?;
        let attestation_id = splitted
            .get(2)
            .ok_or(Error::Generic("Inpropper datum id format".into()))?
            .to_owned();

        Ok(AttestationDatumId::new(testator_id, attestation_id))
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

impl fmt::Display for SignedAttestationDatum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ad_str = serde_json::to_string(&self.at_datum).unwrap();
        let s = &ad_str[1..ad_str.len() - 1];

        write!(
            f,
            "{{{}, \"proof\": {}}}",
            s,
            serde_json::to_string(&self.proof).unwrap()
        )
    }
}

impl SignedAttestationDatum {
    pub fn get_signature(&self) -> Result<Vec<u8>, Error> {
        base64::decode_config(self.proof.signature.clone(), URL_SAFE)
            .map_err(|e| Error::Decode64Error(e))
    }

    pub fn get_issuer(&self) -> Result<String, Error> {
        Ok(self.at_datum.datum.issuer.clone())
    }

    pub fn get_datum(&self) -> Datum {
        self.at_datum.get_datum()
    }

    pub fn get_attestation_datum(&self) -> Result<String, Error> {
        serde_json::to_string(&self.at_datum).map_err(|_| Error::Generic("serde error".into()))
    }

    pub fn to_formatted_string(&self) -> Result<String, Error> {
        Ok(format!("{}", self))
    }

    pub fn serialize(&self) -> Result<String, Error> {
        serde_json::to_string(&self).map_err(|e| Error::Generic(e.to_string()))
    }

    pub fn deserialize(msg: &str) -> Result<SignedAttestationDatum, Error> {
        serde_json::from_str(msg).map_err(|e| Error::Generic(e.to_string()))
    }
}

#[test]
pub fn test_attestation_id_serialization() -> Result<(), Error> {
    let issuer_pref = "D5bw5KrpU2xRc3Oi4rsyBK9By6aotmXU0fNEybJbja1Q";
    let msg_str = "hi there";
    let ad = AttestationDatum::new(msg_str, issuer_pref);
    let id = ad.id;

    let ser_id = serde_json::to_string(&id).unwrap();
    assert_eq!(ser_id, "\"did:keri:D5bw5KrpU2xRc3Oi4rsyBK9By6aotmXU0fNEybJbja1Q/attestationId/jabUza-EpwNOQGALxFtFiMjC6PYdxlJqQtsI9E24uiI=\"");

    let deser_id = AttestationDatumId::from_str(&ser_id).unwrap();
    assert_eq!(deser_id.testator_id, id.testator_id);
    assert_eq!(deser_id.attestation_id, id.attestation_id);

    Ok(())

}

#[test]
pub fn test_signed_datum_serialization() -> Result<(), Error> {
    let sd_str = r#"{"AttestationDatumId":"did:keri:DoQa-mkiBs5kDaSjbONUpryZKAJ4zGFn9EMHJPXykDA0/attestationId/vPjipY4kdlyt9e-p5SM7N_X6DQQD2VEuIfF9Wnrx3w4=","AttestedDatumSources":["did:keri:DoQa-mkiBs5kDaSjbONUpryZKAJ4zGFn9EMHJPXykDA0/attestationId/sourceID"],"Datum":{"issuer":"DoQa-mkiBs5kDaSjbONUpryZKAJ4zGFn9EMHJPXykDA0","message":"Some vc"},"proof":{"signature":"byfYjUug5s0fgwhQuzX4C03G6BwWYi7BMrd-ZoJC8AAuDEYg8duM1iNFn6_ZaTwlAW1QrMWbpGO9_hBvSAF4DQ=="}}"#;
    let sd = SignedAttestationDatum::deserialize(sd_str)?;
    assert_eq!(sd.serialize().unwrap(), sd_str);

    Ok(())
}
