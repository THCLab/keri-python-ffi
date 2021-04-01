# keri-python-ffi

## Usage

### Prerequisits:

    pip3 install blake3 

### Build

Run script from `scripts/build_python.sh`

Output `.so` file is copied to `ffi/python/libs` folder.

### Examples
To run example go to `ffi/python` and run:

    python3 controller_example.py

#### Preview
![entity example](../assets/entity_example.gif?raw=true)

To run issuer and holder example go to `ffi/python/crudential_example` and run:

    python3 issuer.py

Open another termianl and run:

    python3 holder.py

#### Preview
![issuer holder example](../assets/issuer_holder_example.gif?raw=true)

For more examples check `ffi/python` folder.
