from libs.libkel_utils import Controller 
import tempfile
import json

bob_temp_dir = tempfile.TemporaryDirectory()
seeds = "[\"cwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y=\", \"lntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8=\"]"
temp_provider = tempfile.TemporaryDirectory()
provider_path =  "./adr_db"

print("\n" +provider_path+"\n")
# bob = Controller.new_from_seeds(bob_temp_dir.name, 'localhost:3456', seeds, temp_provider)
bob = Controller.new(bob_temp_dir.name, 'localhost:3456', provider_path)
bob.run()

print("\nBobs prefix: " + bob.get_prefix() + "\n")

# get did doc.
print("Bob's current diddoc: ")
ddoc = bob.get_did_doc(bob.get_prefix())
print(ddoc)

# update keys
print("Updating keys...\n")
bob.update_keys()

# get did doc.
print("Diddoc after rotation: ")
ddoc = bob.get_did_doc(bob.get_prefix())
print(ddoc)

bob_temp_dir.cleanup()