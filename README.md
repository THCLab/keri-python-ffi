# keri-python-ffi

## Usage

### Prerequisits:

    pip3 install wonderwords

### Build

Run script from `scripts/build_python.sh`

Output `.so` file is copied to `ffi/python/libs` folder.

Go to `ffi/python/crudential_example` and run:

    python3 issuer.py

Open another termianl and run:

    python3 holder.py

To rotate the key on the issuer side send `ROT` command over TCP

    echo ROT | netcat localhost 5621

For more example check `ffi/python` folder.

## Demo
The following preview are `issuer.py` and `holder.py` examples.

![Demo Animation](../assets/issuer_holder_example.gif?raw=true)
