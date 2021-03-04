#!/usr/bin/env python3
import sys
sys.path.append("..")
from libs.libkel_utils import Entity
import tempfile
import base64
import json
from pprint import pprint

verifier_temp_dir = tempfile.TemporaryDirectory()
temp_provider = "./adr_db"
verifier = Entity.new(verifier_temp_dir.name, 'localhost:3456', temp_provider)

print("\nHolder: did:keri:" + verifier.get_prefix() + "\n")

with open('buffor.py', 'r') as file:
    crud = file.read()
crudential = json.loads(crud)
print("Got VC: \n" + json.dumps(crudential, indent=4, sort_keys=True) + "\n")
    
issuer = crudential['issuer'].split(":")[2]
msg = crudential['msg']
signature = crudential['signature']

verification = verifier.verify(issuer, msg, signature)
print("Issuer's DIDDoc: \n" + json.dumps(json.loads(verifier.get_did_doc(issuer)), indent=4, sort_keys=True) + "\n")

if verification:
    print("Signature is verified\n")
else :
    print("Wrong signature\n")

verifier_temp_dir.cleanup()