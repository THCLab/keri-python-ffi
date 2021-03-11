#!/usr/bin/env python3
import sys
sys.path.append("..")
from libs.libkel_utils import Entity
import tempfile
import base64
import json
import random

temp_dir = tempfile.TemporaryDirectory()
temp_address_provider = "./adr_db"
port = str(random.randint(1000, 9999))
adress = ":".join(["localhost", port])
entity = Entity.new(temp_dir.name, adress, temp_address_provider)
print("\nEntity: did:keri:" + entity.get_prefix() + "\n")

entity_id = ":".join(["did", "keri", entity.get_prefix()])

entity.run()

while(True):
  command = "\trot - update keys \n\tkel - prints key event log \n\tdid <PREFIX> - prints did document of did:keri:<PREFIX> entity \n" 
  val = input("\nAvailable commands \n" + command)

  if val == "rot":
    entity.update_keys()
    print("Keys updated\n")
  elif val == "kel":
    print(entity.get_kerl() + "\n")
  elif val[:3] == "did":
    inp = val.split(" ")
    ddoc = entity.get_did_doc(inp[1])
    formated_ddoc = json.dumps(json.loads(ddoc), indent=4, sort_keys=True)
    print("\n" + "did document: \n" + formated_ddoc + "\n")