from libs.libkel_utils import Entity
import tempfile
import ed25519
import base64

bob_temp_dir = tempfile.TemporaryDirectory()
seeds = "[\"cwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y=\", \"lntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8=\"]"
temp_provider = "./adr_db"
bob = Entity.new(bob_temp_dir.name, 'localhost:3456', seeds, temp_provider)

print("\nBobs prefix: " + bob.get_prefix() + "\n")

# get did doc.
print("Bob's current diddoc: ")
print(bob.get_did_doc(bob.get_prefix()) + "\n")

# update keys
print("Updating keys...\n")
bob.update_keys()

# get did doc.
print("Diddoc after rotation: ")
print(bob.get_did_doc(bob.get_prefix()) + "\n")

print("Eve's Diddoc: ")
print(bob.get_did_doc("DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA") + "\n")

# append ixn to kerl
print("Appending ixn to kel...\n")
bob.append("hi")

print("Bob's KERL: ")
print(bob.get_kerl() + "\n")

# get did doc.
print("Diddoc after interaction: ")
print(bob.get_did_doc(bob.get_prefix()) + "\n")

bob_temp_dir.cleanup()