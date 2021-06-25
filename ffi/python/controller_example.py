#!/usr/bin/env python3
import sys
sys.path.append("..")
from libs.libkeri_ecosystem import Controller, SignatureState, SignedAttestationDatum
import tempfile
import base64
import json
import random
import os
import requests
import blake3

temp_dir = tempfile.TemporaryDirectory()
temp_address_provider = "./adr_db"
port = str(random.randint(1000, 9999))
adress = ":".join(["localhost", port])
controller = Controller.new(temp_dir.name, adress, temp_address_provider)
print("\nController: did:keri:" + controller.get_prefix() + "\n")

controller_id = ":".join(["did", "keri", controller.get_prefix()])
b64_vc_hash = ""

# Last signed ACDC
vc = ""
controller.run()

signed_data = SignedAttestationDatum.default()

while(True):
  command = """
  kel - print key event log
  sign <SCHEMA> <MESSAGE> - sign given message and create VC
  upload - uploads data to DSH\n\n"""
  # verify - verify signature of last signed VC\n\n"""
  # rot - update keys

  val = input("Available commands:" + command)

  # if val == "rot":
  #   # rotate keys
  #   controller.update_keys()
  #   print("Keys updated. Current KEL: \n" + controller.get_kerl())
  

  if val == "kel":
    # print kel
    print(controller.get_kerl() + "\n")
  
  # elif val == "rev":
  #   # revoke last vc
  #   controller.revoke_vc(vc)
  #   vc_hash = blake3.blake3(bytes(vc, encoding='utf8')).digest()
  #   b64_vc_hash = base64.urlsafe_b64encode(vc_hash).decode()

  #   print("VC of digest: "+ b64_vc_hash + " was revoked. Current TEL:")
  #   print(controller.get_formatted_tel(b64_vc_hash) + "\n")
  
  # elif val == "tel":
  #   # print tel of last signed vc
  #   if len(b64_vc_hash) > 0:
  #     print("vc digest: "+ b64_vc_hash)
  #     print(controller.get_formatted_tel(b64_vc_hash) + "\n")
  #   else:
  #     print("No vc has been signed yet\n")
  
  elif val[:4] == "sign":
    inp = val.split(" ", 2)
    # try:
    schema = inp[1]
    message = inp[2]
    try:
      json.loads(message)
    
      signed_data = controller.issue_vc(schema, message)

      # create crudential and write it to file
      # TODO use some better way of sending crudential than the file.
      with open('last_crudential', 'w') as file:
        ser = str(signed_data)
        file.write(ser + "\n")

      # Pretty printing the vc json
      # vc_dict = json.loads(str(signed_data))
      # pretty_vc = json.dumps(vc_dict, indent=4, sort_keys=True)
      print("Issuer creates the ACDC: \n" )

      vc = signed_data.get_attestation_datum()

      # Pretty printing the vc json
      vc_dict = json.loads(str(signed_data.get_attestation_datum()))
      pretty_vc = json.dumps(vc_dict, indent=4, sort_keys=True)
      print(pretty_vc)
      signature = base64.urlsafe_b64encode(bytes(signed_data.get_signature())).decode('ascii')
      print("signature: " + signature + "\n")

      vc_hash = blake3.blake3(bytes(vc, encoding='utf8')).digest()
      b64_vc_hash = base64.urlsafe_b64encode(vc_hash).decode()
      print("Adding ACDC hash to KEL: " + str(b64_vc_hash))
      print("Current KEL:\n" + controller.get_kerl())
    except:
      print("Incorect message format. Should be valid json")
    # except:
      # print("No message to sign\n")
 
  # elif val[:6] == "diddoc":
  #   # get did document for given prefix
  #   inp = val.split(" ")
  #   try:
  #     prefix = inp[1].strip()
  #     ddoc = controller.get_did_doc(prefix)
  #     formated_ddoc = json.dumps(json.loads(ddoc), indent=4, sort_keys=True)
  #     print("\n" + "did document: \n" + formated_ddoc + "\n")
  #   except:
  #     print("Missing prefix\n")
  
  elif val == "upload":

    headers = {
      'Content-type': 'application/json',
    }

    result = requests.post('https://criteria-search.argo.colossi.network/api/v1/entities')
    res = result.json()
    id = res['result']['id']

    data = "{" + "\"d\":"+signed_data.get_datum() + ",\"x\":\"" + signed_data.get_schema() + "\"}"
    address = "https://criteria-search.argo.colossi.network/api/v1/entities/" + str(id) + "/data"

    response = requests.post(address, headers=headers, data=data)
    print("Data uploaded successfully")
    
temp_dir.cleanup()
dir.cleanup()