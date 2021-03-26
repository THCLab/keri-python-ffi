#!/usr/bin/env python3
import sys
sys.path.append("..")
from libs.libkel_utils import Controller 
import tempfile
import base64
import json
import random
import os

temp_dir = tempfile.TemporaryDirectory()
temp_address_provider = "./adr_db"
port = str(random.randint(1000, 9999))
adress = ":".join(["localhost", port])
controller = Controller.new(temp_dir.name, adress, temp_address_provider)
print("\nController: did:keri:" + controller.get_prefix() + "\n")

controller_id = ":".join(["did", "keri", controller.get_prefix()])

controller.run()

while(True):
  command = """
  rot - update keys
  kel - prints key event log
  diddoc <PREFIX> - prints did document of did:keri:<PREFIX> controller
  sign <MESSAGE> - sign given message and creates VC
  verify - verify signature of last signed VC\n\n"""
  val = input("Available commands:" + command)

  if val == "rot":
    # rotate keys
    controller.update_keys()
    print("Keys updated\n")
  elif val == "kel":
    # print kel
    print(controller.get_kerl() + "\n")
  elif val[:4] == "sign":
    # sign message with current key
    inp = val.split(" ", 1)
    message = inp[1]
    signature = controller.sign(message)
    b64_signature = base64.urlsafe_b64encode(bytes(signature)).decode("utf-8")
    # create crudential and write it to file
    # TODO use some better way of sending crudential than the file.
    crudential = {"issuer": ":".join(["did", "keri", controller.get_prefix()]), "msg": message, "signature": b64_signature}
    with open('last_crudential', 'w') as file:
      file.write(json.dumps(crudential))
    print("Create VC: \n" + json.dumps(crudential, indent=4, sort_keys=True) + "\n")
  elif val[:6] == "verify":
    # read crudential from file and verify the signature
    with open('last_crudential', 'r') as file:
      crud = file.read()
    crudential = json.loads(crud)
    print("Got VC: \n" + json.dumps(crudential, indent=4, sort_keys=True))
        
    issuer = crudential['issuer'].split(":")[2]
    msg = crudential['msg']
    signature = crudential['signature']

    verification = controller.verify(issuer, msg, signature)
    if verification:
      print("Signature is verified\n")
    else :
      print("Wrong signature\n")
  elif val[:6] == "diddoc":
    # get did document for given prefix
    inp = val.split(" ")
    ddoc = controller.get_did_doc(inp[1].strip())
    formated_ddoc = json.dumps(json.loads(ddoc), indent=4, sort_keys=True)
    print("\n" + "did document: \n" + formated_ddoc + "\n")

temp_dir.cleanup()
dir.cleanup()