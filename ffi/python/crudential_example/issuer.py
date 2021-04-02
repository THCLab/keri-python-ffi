#!/usr/bin/env python3
import sys
sys.path.append("..")
from libs.libkel_utils import Controller
import tempfile
import base64
import json
import blake3

# Setup issuer
issuer_temp_dir = tempfile.TemporaryDirectory()
temp_address_provider = "./adr_db"
issuer = Controller.new(issuer_temp_dir.name, 'localhost:5621', temp_address_provider)
print("Issuer: did:keri:" + issuer.get_prefix() + "\n")

# Construct vc
issuer_id = ":".join(["did", "keri", issuer.get_prefix()])
message = "hello there" 
vc = {"issuer": issuer_id, "message": message }
vc_str = json.dumps(vc)

print("Issuer signs the vc: " + vc_str + "\n")

signature = issuer.issue_vc(vc_str)
ver_method = issuer_id
b64_signature = base64.urlsafe_b64encode(bytes(signature)).decode("utf-8")
proof = {"signature": b64_signature}
vc["proof"] = proof

print("Create VC: \n" + json.dumps(vc, indent=4, sort_keys=True) + "\n")

vc_hash = blake3.blake3(bytes(vc_str, encoding='utf8')).digest()
b64_vc_hash = base64.urlsafe_b64encode(vc_hash).decode()
print("VC hash: " + str(b64_vc_hash) + "\n")

# Simulate sending the VC
with open('buffor', 'w') as file:
    file.write(json.dumps(vc))

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
    print("Keys rotated. Current KEL:")
    print(issuer.get_formatted_kerl())
  elif val == "rev":
    # revoke last vc
    issuer.revoke_vc(vc_str)
    print("VC of digest: "+ b64_vc_hash + " was revoked. Current TEL:")
    print(issuer.get_formatted_tel(b64_vc_hash) + "\n")
  elif val == "kel":
    print(issuer.get_formatted_kerl())
  elif val == "tel":
    print("vc digest: "+ b64_vc_hash)
    print(issuer.get_formatted_tel(b64_vc_hash) + "\n")
