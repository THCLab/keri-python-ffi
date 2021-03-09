#!/usr/bin/env python3
import sys
sys.path.append("..")
from libs.libkel_utils import Entity
import tempfile
import base64
import json

issuer_temp_dir = tempfile.TemporaryDirectory()
temp_address_provider = "./adr_db"
issuer = Entity.new(issuer_temp_dir.name, 'localhost:5621', temp_address_provider)
print("\nIssuer: did:keri:" + issuer.get_prefix() + "\n")

issuer_id = ":".join(["did", "keri", issuer.get_prefix()])
message = "hello there" 

print("Issuer signs the message: " + message + "\n")

signature = issuer.sign(message)
b64_signature = base64.urlsafe_b64encode(bytes(signature)).decode("utf-8")

crudential = {"issuer": issuer_id, "msg": message, "signature": b64_signature}
print("Create VC: \n" + json.dumps(crudential, indent=4, sort_keys=True) + "\n")

issuer.verify(issuer.get_prefix(), message, b64_signature)

with open('buffor.py', 'w') as file:
    file.write(json.dumps(crudential))

issuer.run()