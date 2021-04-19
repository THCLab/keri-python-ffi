#!/usr/bin/env python3
import sys
sys.path.append("..")
from libs.libkeri_ecosystem import Controller, SignatureState, SignedAttestationDatum, SharedThing, Pack
import tempfile
import base64
import random
import os
import blake3

temp_dir = tempfile.TemporaryDirectory()
temp_address_provider = "./adr_db"
port = str(random.randint(1000, 9999))

# Setup actors
print("\n====================================================")
print("\tSetup actors: ")
print("====================================================\t")
address = ":".join(["localhost", port])
sender = Controller.new(temp_dir.name, address, temp_address_provider)
print("\nSender: did:keri:" + sender.get_prefix() + "\n")

port = str(random.randint(1000, 9999))

address = ":".join(["localhost", port])
receiver = Controller.new(temp_dir.name, address, temp_address_provider)
print("\nReceiver: did:keri:" + receiver.get_prefix() + "\n")

port = str(random.randint(1000, 9999))

address = ":".join(["localhost", port])
courier = Controller.new(temp_dir.name, address, temp_address_provider)
print("\nCourier: did:keri:" + courier.get_prefix() + "\n")

port = str(random.randint(1000, 9999))

address = ":".join(["localhost", port])
storage = Controller.new(temp_dir.name, address, temp_address_provider)
print("\nStorage manager: did:keri:" + storage.get_prefix() + "\n")

port = str(random.randint(1000, 9999))

address = ":".join(["localhost", port])
courier2 = Controller.new(temp_dir.name, address, temp_address_provider)
print("\nCourier: did:keri:" + courier2.get_prefix() + "\n")

pack = Pack.new("localhost:1111")
input("Press enter to continue...")

# ========================================================
# Sender is filling the send form
# Incept pack kel with sender key as current key and courier public key as next.
# Insert to pack kel interaction event with document hash.
# ========================================================
print("\n====================================================")
print("\tSend form is filled by the sender")
print("====================================================\n")
pack.incept_thing(sender, courier, receiver)
input("\nPress enter to continue...")

# ========================================================
# Receiving the package by the courier in progress...
# Rotate pack kel with courier key as current key and storage public key as next.
# Insert to pack kel interaction event with document hash.
# ========================================================
print("\n====================================================")
print("\tReceiving te package by the courier in progress...")
print("===================================================\n")
pack.transfer_ownership(courier, storage, "Got pack from " + courier.get_prefix())
input("\nPress enter to continue...")

# ========================================================
# Storaging the package
# Rotate pack kel with storage key as current key and courier2 public key as next.
# Insert to pack kel interaction event with document hash.
# ========================================================
print("\n====================================================")
print("\tStoraging the package")
print("====================================================\n")
pack.transfer_ownership(storage, courier2, "Pack storaged successfully by " + storage.get_prefix())
input("\nPress enter to continue...")

# ========================================================
# Released to delivery
# Rotate pack kel with storage key as current key and courier2 public key as next.
# Insert to pack kel interaction event with document hash.
# ========================================================
print("\n====================================================")
print("\tReleasing to delivery")
print("====================================================\n")
pack.transfer_ownership(courier2, receiver, "Package released to delivery to " + receiver.get_prefix())
input("\nPress enter to continue...")

# ========================================================
# Package received by the receiver
# Rotate pack kel with receiver public key as current.
# Insert to pack kel interaction event with document hash.
# ========================================================
print("\n====================================================")
print("\tPackage received by the receiver")
print("====================================================\n")
pack.receive(receiver, "Package was received by " + receiver.get_prefix())
print("\nPackage received succesfully!")



