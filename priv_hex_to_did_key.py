import sys
import os
from eth_keys import keys
import base58

def privHexForDidKey(key_did, search_dir):
    
    files = os.listdir(search_dir)
    for file in files:
        with open(search_dir + '/' + file) as f:
            priv_hex = f.read().rstrip()
            if privHexToDidKey(priv_hex) == key_did:
                return priv_hex

    return None

def privHexFileToDidKey(key_file):

    if not os.path.exists(key_file):
        return None

    priv_hex = None
    with open(key_file) as f:
        priv_hex = f.read().rstrip()

    return privHexToDidKey(priv_hex)

def privHexToDidKey(key_hex):

    if not key_hex[0:2] == "0x":
        raise Exception("Key should being with 0x")

    if not len(key_hex) == 66:
        raise Exception("Key should be 66 chars long (0x + 32 bytes)")

    pk = keys.PrivateKey(bytes.fromhex(key_hex[2:]))
    pub = pk.public_key.to_compressed_bytes()

    prepend = bytes.fromhex("e701");
    pub_bytes = bytearray(prepend)
    pub_bytes.extend(pub)
    b58encoded = base58.b58encode(pub_bytes)

    return "did:key:z" + str(b58encoded.decode('utf-8'))

if __name__ == '__main__':

    if len(sys.argv) != 2:
        raise Exception("Usage: python priv_hex_to_did_key.py <pk file>")

    key_file = sys.argv[1]
    did_key = privHexFileToDidKey(key_file)
    print(did_key)

