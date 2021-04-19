#!/usr/bin/env python3
import sys
sys.path.append("..")
from libs.libkeri_ecosystem import Controller, SignatureState, SignedAttestationDatum, SharedThing
import tempfile

temp_dir = tempfile.TemporaryDirectory()

thing = SharedThing.init_and_run("localhost:1111", temp_dir.name)
print("Package monitor\n")
while True:
    pass




