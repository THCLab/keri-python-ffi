#!/usr/bin/env python3
import sys
sys.path.append("..")
from libs.libkel_utils import Controller, SignatureState
import tempfile
import base64
import json
import random
import os
import blake3

temp_dir = tempfile.TemporaryDirectory()
temp_address_provider = "./adr_db"
port = str(random.randint(1000, 9999))
adress = ":".join(["localhost", port])
controller = Controller.new(temp_dir.name, adress, temp_address_provider)
print("\nController: did:keri:" + controller.get_prefix() + "\n")

controller_id = ":".join(["did", "keri", controller.get_prefix()])

# Last signed VC
vc = ""

controller.run()


while(True):
  command = """
  rot - update keys
  kel - print key event log
  rev - revoke last VC
  tel - print tel of last VC
  diddoc <PREFIX> - print did document of did:keri:<PREFIX> controller
  sign <MESSAGE> - sign given message and create VC\n\n"""
  # verify - verify signature of last signed VC\n\n"""

  val = input("Available commands:" + command)

  if val == "rot":
    # rotate keys
    controller.update_keys()
    print("Keys updated. Current KEL: \n" + controller.get_kerl())
  
  elif val == "kel":
    # print kel
    print(controller.get_kerl() + "\n")
  
  elif val == "rev":
    # revoke last vc
    controller.revoke_vc(vc)
    vc_hash = blake3.blake3(bytes(vc, encoding='utf8')).digest()
    b64_vc_hash = base64.urlsafe_b64encode(vc_hash).decode()

    print("VC of digest: "+ b64_vc_hash + " was revoked. Current TEL:")
    print(controller.get_formatted_tel(b64_vc_hash) + "\n")
  
  elif val == "tel":
    print("vc digest: "+ b64_vc_hash)
    print(controller.get_formatted_tel(b64_vc_hash) + "\n")
  
  elif val[:4] == "sign":
    inp = val.split(" ", 1)
    message = inp[1]

    # Construct crudential
    issuer_id = ":".join(["did", "keri", controller.get_prefix()])
    vc = {"issuer": issuer_id, "message": message }
    vc_str = json.dumps(vc)

    print("Issuer signs the vc: " + vc_str + "\n")

    signature = controller.issue_vc(vc_str)
    b64_signature = base64.urlsafe_b64encode(bytes(signature)).decode("utf-8")
    proof = {"signature": b64_signature}
    vc["proof"] = proof

    # create crudential and write it to file
    # TODO use some better way of sending crudential than the file.
    with open('last_crudential', 'w') as file:
      file.write(json.dumps(vc) + "\n")
    print("Create VC: \n" + json.dumps(vc, indent=4, sort_keys=True) + "\n")
    vc_hash = blake3.blake3(bytes(vc_str, encoding='utf8')).digest()
    b64_vc_hash = base64.urlsafe_b64encode(vc_hash).decode()
    print("VC hash:\n\t" + str(b64_vc_hash) + "\n")
    print("Current KEL:\n" + controller.get_kerl())
    vc = vc_str
  
  # elif val[:6] == "verify":
  #   # read crudential from file and verify the signature
  #   with open('last_crudential', 'r') as file:
  #     crud = file.read()
  #   crudential = json.loads(crud)
  #   print("Got VC: \n" + json.dumps(crudential, indent=4, sort_keys=True))
        
  #   # Deconstruct VC to get issuer, message and proof
  #   issuer = crudential['issuer'].split(":")[2]
  #   msg = crudential['message']
  #   proof = crudential['proof']
  #   b64_signature = proof['signature']

  #   signature = [x for x in base64.urlsafe_b64decode(b64_signature)]
  #   # Choose only issuer and message field
  #   vc = {key: crudential[key] for key in ["issuer", "message"]}
  #   vc_str = json.dumps(vc)

  #   print("Asking did:keri:" + issuer + " for KEL and TEL:" )

  #   verification = controller.verify_vc(issuer, vc_str, signature)
  #   if verification == SignatureState.Ok:
  #     print("VC is signed by " + issuer + "\n")
  #   elif verification == SignatureState.Revoked:
  #     vc_hash = blake3.blake3(bytes(msg, encoding='utf8')).digest()
  #     vc_b64_hash = str(base64.urlsafe_b64encode(vc_hash).decode())
  #     print("VC of digest " + vc_b64_hash + " has been revoked\n")
  #   elif verification == SignatureState.Wrong:
  #     print("Signature is wrong. VC is not signed by " + issuer + "\n")

  elif val[:6] == "diddoc":
    # get did document for given prefix
    inp = val.split(" ")
    ddoc = controller.get_did_doc(inp[1].strip())
    formated_ddoc = json.dumps(json.loads(ddoc), indent=4, sort_keys=True)
    print("\n" + "did document: \n" + formated_ddoc + "\n")
  
temp_dir.cleanup()
dir.cleanup()