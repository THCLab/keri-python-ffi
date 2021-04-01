#!/usr/bin/env python3
import sys
sys.path.append("..")
from libs.libkel_utils import Controller, SignatureState 
import tempfile
import base64
import json
import blake3

verifier_temp_dir = tempfile.TemporaryDirectory()
temp_provider = "./adr_db"
verifier = Controller.new(verifier_temp_dir.name, 'localhost:3456', temp_provider)
verifier.run()

print("\nHolder: did:keri:" + verifier.get_prefix() + "\n")

with open('buffor', 'r') as file:
    crud = file.read()
crudential = json.loads(crud)
print("Got VC: \n" + json.dumps(crudential, indent=4, sort_keys=True))
    
issuer = crudential['issuer'].split(":")[2]
msg = crudential['msg']
signature = [x for x in base64.urlsafe_b64decode(crudential['signature'])]

print("Asking did:keri:" + issuer + " for KEL and TEL:" )
verification = verifier.verify_vc(issuer, msg, signature)

# print("\nIssuer's DIDDoc: \n" + json.dumps(json.loads(verifier.get_did_doc(issuer)), indent=4, sort_keys=True) + "\n")


if verification == SignatureState.Ok:
    print("VC is signed by " + issuer + "\n")
elif verification == SignatureState.Revoked:
    vc_hash = blake3.blake3(bytes(msg, encoding='utf8')).digest()
    vc_b64_hash = str(base64.urlsafe_b64encode(vc_hash).decode())
    print("VC of digest " + vc_b64_hash + " has been revoked\n")
elif verification == SignatureState.Wrong:
    print("Signature is wrong. VC is not signed by " + issuer + "\n")

verifier_temp_dir.cleanup()