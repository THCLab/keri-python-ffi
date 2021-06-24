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
    crud = file.read().strip()

signed_data = SignedAttestationDatum.deserialize(crud)
print("Got ACDC raw: \n" + crud + "\n")

# Pretty printing the vc json
print("Parsed ACDC:\n")
vc_dict = json.loads(str(signed_data.get_attestation_datum()))
pretty_vc = json.dumps(vc_dict, indent=4, sort_keys=True)
print(pretty_vc)
signature = base64.urlsafe_b64encode(bytes(signed_data.get_signature())).decode('ascii')
print("signature: " + signature + "\n")

issuer = signed_data.get_issuer()

print("Asking did:keri:" + issuer + " for KEL:" )
verification = verifier.verify_vc(signed_data)

if verification:
    print("VC is signed by " + issuer + "\n")
else:
    print("Signature is wrong. VC is not signed by " + issuer + "\n")

verifier_temp_dir.cleanup()