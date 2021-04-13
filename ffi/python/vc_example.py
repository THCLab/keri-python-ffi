from libs.libkeri_ecosystem import Controller 
import tempfile
import json
import base64

issuer_temp_dir = tempfile.TemporaryDirectory()
temp_provider = tempfile.TemporaryDirectory()
provider_path =  "./adr_db"

# Create and run issuer controller
issuer = Controller.new(issuer_temp_dir.name, 'localhost:3456', provider_path)
issuer.run()

issuer_prefix = issuer.get_prefix()
msg = "here is the message"
# Sign message by issuer
signature = issuer.issue_vc(msg)
b64signature = base64.urlsafe_b64encode(bytes(signature)).decode('utf8')
print("\nIssuer's prefix: " + issuer.get_prefix() + "\nmessage: " + msg + "\nsignature: " + b64signature + "\n")

# Create and run verifier
verifier_temp_dir = tempfile.TemporaryDirectory()
verifier = Controller.new(verifier_temp_dir.name, 'localhost:1212', provider_path)
verifier.run()
print("Verifier: did:keri:" + verifier.get_prefix())


# Verify message and signature by verifier
print("\nVerifier verifies the message and signature...")
ver = verifier.verify_vc(issuer_prefix, msg, signature)
if ver:
    print("\nSignature is valid")
else:
    print("\nWrong signature")

# Revoke the message
print("\nIssuer revokes the vc.")
issuer.revoke_vc(msg)

# Try to verify it again by verifier.
print("\nVerifing the vc again...")
ver = verifier.verify_vc(issuer_prefix, msg, signature)
if ver:
    print("\nSignature is valid")
else:
    print("\nWrong signature")

