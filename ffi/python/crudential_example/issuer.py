#!/usr/bin/env python3
import sys
sys.path.append("..")
from libs.libkel_utils import Controller
import tempfile
import base64
import json
import blake3

issuer_temp_dir = tempfile.TemporaryDirectory()
temp_address_provider = "./adr_db"
issuer = Controller.new(issuer_temp_dir.name, 'localhost:5621', temp_address_provider)
print("Issuer: did:keri:" + issuer.get_prefix() + "\n")

issuer_id = ":".join(["did", "keri", issuer.get_prefix()])
message = "hello there" 

print("Issuer signs the message: " + message + "\n")

signature = issuer.issue_vc(message)

b64_signature = base64.urlsafe_b64encode(bytes(signature)).decode("utf-8")

crudential = {"issuer": issuer_id, "msg": message, "signature": b64_signature}
print("Create VC: \n" + json.dumps(crudential, indent=4, sort_keys=True) + "\n")

vc_hash = blake3.blake3(bytes(message, encoding='utf8')).digest()
b64_vc_hash = base64.urlsafe_b64encode(vc_hash).decode()
print("VC hash: " + str(b64_vc_hash) + "\n")

with open('buffor', 'w') as file:
    file.write(json.dumps(crudential))

issuer.run()
while(True):

  command = """Availabla commands:
      rot - update keys
      kel - print current kel
      rev - revoke last VC
      tel - print tel of last VC\n\n"""
  val = input(command)

  if val == "rot":
    # rotate keys
    issuer.update_keys()
    print("Keys updated\n")
  elif val == "rev":
    # revoke last vc
    issuer.revoke_vc(message)
    print("VC revoked\n")
  elif val == "kel":
    print(issuer.get_formatted_kerl())
  elif val == "tel":
    print("TEL of vc of digest "+ b64_vc_hash)
    print(issuer.get_formatted_tel(b64_vc_hash) + "\n")
