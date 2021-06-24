use acdc::{attestation::{Attestation, AttestationId}, datum::Message, identifier::{BasicIdentifier, Identifier}, signed_attestation::{KeyType, Proof, SignedAttestation}};

use crate::error::Error;

pub fn create_attestation(testator_id: &str, attestation_id: &str, message: &str, schema: &str) -> Result<Attestation<String, Message, String>, Error> {
    // Create testator identifier.
    let testator_id = Identifier::Basic(BasicIdentifier::new(testator_id));

    // Create attestation which will be a source.
    let source_attestation_id: AttestationId = attestation_id.parse().map_err(|e| Error::Generic("Can't parse attestation id".into()))?;
    let datum = Message {
        message: message.into(),
    };
    Ok(
        Attestation::new(source_attestation_id, None, vec![], schema.to_string(), datum, None)
    )
}

pub fn sign_attestation(att: Attestation<String, Message, String>, signature: Vec<u8>) -> Result<SignedAttestation<String, Message, String>, Error> {
    let proof = Proof::new(KeyType::Ed25519, &signature);
    Ok(SignedAttestation::new(att, proof))
}

// Wrapper for python ffi.
pub struct SignedAttestationDatum {
    pub sa : SignedAttestation<String, Message, String>
}

impl SignedAttestationDatum {
    pub fn to_string(&self) -> Result<String, Error> {
        Ok(self.sa.to_string())
    }

    pub fn get_attestation_datum(&self) -> Result<String, Error> {
        serde_json::to_string(self.sa.get_attestation_datum()).map_err(|e| Error::Generic(e.to_string()))
    }

    pub fn deserialize(msg: &str) -> Result<SignedAttestationDatum, Error> {
        let sa = msg.parse::<SignedAttestation<String, Message, String>>().map_err(|e| Error::Generic(e.to_string()))?;
        Ok(SignedAttestationDatum {sa})
    }
    pub fn get_issuer(&self) -> Result<String, Error> {
            Ok(self.sa.get_id().testator_id.get_id())
    }

    pub fn get_signature(&self) -> Result<Vec<u8>, Error> {
        self.sa.get_signature().map_err(|e| Error::Generic(e.to_string()))
    }

    pub fn get_schema(&self) -> Result<String, Error> {
        self.sa.get_schema().map_err(|e| Error::Generic("Can't get schema".into()))
    }
    pub fn get_datum(&self) -> Result<String, Error> {
        self.sa.get_datum().map_err(|e| Error::Generic("Can't get schema".into()))
    }
}