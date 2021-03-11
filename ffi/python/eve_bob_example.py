from libs.libkel_utils import Entity
import tempfile
import json

bob_temp_dir = tempfile.TemporaryDirectory()
seeds = "[\"cwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y=\", \"lntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8=\"]"
temp_provider = "./adr_db"
bob = Entity.new_from_seeds(bob_temp_dir.name, 'localhost:3456', seeds, temp_provider)

print("\nBobs prefix: " + bob.get_prefix() + "\n")

# get did doc.
print("Bob's current diddoc: ")
ddoc = bob.get_did_doc(bob.get_prefix())
print( json.dumps(json.loads(ddoc), indent=4, sort_keys=True) + "\n")

# update keys
print("Updating keys...\n")
bob.update_keys()

# get did doc.
print("Diddoc after rotation: ")
ddoc = bob.get_did_doc(bob.get_prefix())
print( json.dumps(json.loads(ddoc), indent=4, sort_keys=True) + "\n")

eve_temp_dir = tempfile.TemporaryDirectory()
seeds = "[\"rwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc=\", \"6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q=\"]"
eve = Entity.new_from_seeds(eve_temp_dir.name, 'localhost:5621', seeds, temp_provider)
print("\nEve's prefix " + eve.get_prefix())

bob.run()
eve.run()

eve_pref = str(eve.get_prefix())
eve_ddoc = bob.get_did_doc(eve_pref)
print("Eve's Diddoc: ")
print(json.dumps(json.loads(eve_ddoc), indent=4, sort_keys=True) + "\n")

bob_temp_dir.cleanup()
eve_temp_dir.cleanup()