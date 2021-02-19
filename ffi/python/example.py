from libs.libkel_utils import Entity, Key, KeyType
import tempfile
import ed25519
import base64

privKey, pubKey = ed25519.create_keypair()
nextprivKey, nextpubKey = ed25519.create_keypair()

pk = Key(pubKey.to_bytes(), KeyType.ED)
next_pk = Key(nextpubKey.to_bytes(), KeyType.ED)

bob_temp_dir = tempfile.TemporaryDirectory()

bob = Entity(bob_temp_dir.name, '', 'localhost:3456')

# Get icp event to sign.
icp_bytes = bob.incept_keys(pk, next_pk)
print("".join(map(chr, icp_bytes)))

# send back event and signature
signature = privKey.sign(bytes(icp_bytes))
con = bob.confirm_key_update(icp_bytes, signature)

print(bob.get_prefix())

# get did doc.
print("Current diddoc: ")
print(bob.get_did_doc(bob.get_prefix(), 'localhost:3456'))
print("\n")

# update keys
new_nextprivKey, new_nextpubKey = ed25519.create_keypair()
new_current_key = next_pk
new_next_pk = Key(new_nextpubKey.to_bytes(), KeyType.ED)
rot_bytes = bob.update_keys( new_current_key, new_next_pk)
# send back event and signature
signature = nextprivKey.sign(bytes(rot_bytes))
con = bob.confirm_key_update(rot_bytes, signature)

# get did doc.
print("Current diddoc: ")
print(bob.get_did_doc(bob.get_prefix(), 'localhost:3456'))
print("\n")

bob.get_did_doc("D6DTRySatmqcb76RbBnIFqjZ7BZZqcShJfwbB9CzZxdI", 'localhost:5621')

bob_temp_dir.cleanup()