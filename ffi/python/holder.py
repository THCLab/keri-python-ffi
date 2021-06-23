#!/usr/bin/env python3
import sys
sys.path.append("..")
from libs.libkeri_ecosystem import Controller, SignatureState, SignedAttestationDatum 
import tempfile
import base64
import json
import blake3

# Setup holder
verifier_temp_dir = tempfile.TemporaryDirectory()
temp_provider = "./adr_db"
verifier = Controller.new(verifier_temp_dir.name, 'localhost:3456', temp_provider)
verifier.run()

print("\nHolder: did:keri:" + verifier.get_prefix() + "\n")

# Simulate getting the VC
with open('last_crudential', 'r') as file:
    crud = file.read()
print(str(crud))
signed_data = SignedAttestationDatum.deserialize(crud)
print("Got VC: \n" + signed_data.to_string())

issuer = signed_data.get_issuer()

print("Asking did:keri:" + issuer + " for KEL and TEL:" )
verification = verifier.verify_vc(signed_data)

if verification == SignatureState.Ok:
    print("VC is signed by " + issuer + "\n")
elif verification == SignatureState.Revoked:
    vc_str = signed_data.get_attestation_datum()
    vc_hash = blake3.blake3(bytes(vc_str, encoding='utf8')).digest()
    vc_b64_hash = str(base64.urlsafe_b64encode(vc_hash).decode())
    print("VC of digest " + vc_b64_hash + " has been revoked\n")
elif verification == SignatureState.Wrong:
    print("Signature is wrong. VC is not signed by " + issuer + "\n")

verifier_temp_dir.cleanup()