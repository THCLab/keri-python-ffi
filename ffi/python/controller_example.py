#!/usr/bin/env python3
import sys
sys.path.append("..")
from libs.libkel_utils import Controller, SignatureState, SignedAttestationDatum
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
b64_vc_hash = ""

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
    # print tel of last signed vc
    if len(b64_vc_hash) > 0:
      print("vc digest: "+ b64_vc_hash)
      print(controller.get_formatted_tel(b64_vc_hash) + "\n")
    else:
      print("No vc has been signed yet\n")
  
  elif val[:4] == "sign":
    inp = val.split(" ", 1)
    try:
      message = inp[1]
      signed_data = controller.issue_vc(message)

      # create crudential and write it to file
      # TODO use some better way of sending crudential than the file.
      with open('last_crudential', 'w') as file:
        ser = signed_data.serialize()
        file.write(ser + "\n")

      # Pretty printing the vc json
      vc_dict = json.loads(signed_data.serialize())
      pretty_vc = json.dumps(vc_dict, indent=4, sort_keys=True)
      print("Issuer creates the vc: \n" + pretty_vc + "\n")
  
      vc = signed_data.get_attestation_datum()
      vc_hash = blake3.blake3(bytes(vc, encoding='utf8')).digest()
      b64_vc_hash = base64.urlsafe_b64encode(vc_hash).decode()
      print("VC hash:\n\t" + str(b64_vc_hash) + "\n")
      print("Current KEL:\n" + controller.get_kerl())
    except:
      print("No message to sign\n")
 
  elif val[:6] == "diddoc":
    # get did document for given prefix
    inp = val.split(" ")
    try:
      prefix = inp[1].strip()
      ddoc = controller.get_did_doc(prefix)
      formated_ddoc = json.dumps(json.loads(ddoc), indent=4, sort_keys=True)
      print("\n" + "did document: \n" + formated_ddoc + "\n")
    except:
      print("Missing prefix\n")
  
temp_dir.cleanup()
dir.cleanup()