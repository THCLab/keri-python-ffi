from libs.libkel_utils import Entity, Key, KeyType
import tempfile
import ed25519
import base64
# ==========================================
# Eve
# ==========================================
privKey, pubKey = ed25519.create_keypair()
nextprivKey, nextpubKey = ed25519.create_keypair()

pk = Key(pubKey.to_bytes(), KeyType.ED)
next_pk = Key(nextpubKey.to_bytes(), KeyType.ED)

eve_temp_dir = tempfile.TemporaryDirectory()

eve = Entity(eve_temp_dir.name, '', 'localhost:5621')

# Get icp event to sign.
icp_bytes = eve.incept_keys(pk, next_pk)
print("".join(map(chr, icp_bytes)))

# send back event and signature
signature = privKey.sign(bytes(icp_bytes))
con = eve.confirm_key_update(icp_bytes, signature)
eve.run()