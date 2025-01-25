import priv_hex_to_did_key

import os
import urllib.request
import requests
import json
import hashlib
import libipld
from eth_keys import keys
import base64
import argparse
import copy

PLC_CACHE = './cache'
OUT_DIR = './out'

DID_DIRECTORY = 'https://plc.directory'

def loadHistory(did):

    if not os.path.exists(PLC_CACHE):
        os.mkdir(PLC_CACHE)

    # NB You have to get the right endpoint here, BSky service won't tell you about other people's PDSes.
    plc_file = PLC_CACHE + '/' + hashlib.sha256(did.encode()).hexdigest() + '.plc'
    if not os.path.exists(plc_file):
        plc_url = DID_DIRECTORY + '/' + did + '/log/audit'
        urllib.request.urlretrieve(plc_url, plc_file)

    with open(plc_file, mode="rb") as cf:
        return json.load(cf)

def signUpdate(entry, priv_hex):

    sighash = hashlib.sha256(libipld.encode_dag_cbor(entry)).digest()

    pk = keys.PrivateKey(bytes.fromhex(priv_hex[2:]))
    sig = pk.sign_msg_hash(sighash)
    rs = bytearray(sig.r.to_bytes(32, byteorder='big'))
    rs.extend(sig.s.to_bytes(32, byteorder='big'))
    sig_base64 = base64.urlsafe_b64encode(rs).decode('utf-8').replace('=', '')

    # Clone the entry but adding the sig at the start
    new_entry = {"sig": sig_base64}
    for entry_key in entry:
        new_entry[entry_key] = entry[entry_key]

    return new_entry

def calculateCid(entry):
    prepend = bytes.fromhex("01711220")
    hash_bytes = hashlib.sha256(libipld.encode_dag_cbor(entry)).digest()
    cid_bytes = bytearray(prepend)
    cid_bytes.extend(hash_bytes)
    return 'b' + base64.b32encode(cid_bytes).decode('utf-8').lower().replace('=', '')

def calculateDid(entry):
    hash_bytes = hashlib.sha256(libipld.encode_dag_cbor(entry)).digest()
    did_suffix = base64.b32encode(hash_bytes).decode('utf-8').lower()
    return "did:plc:" + did_suffix[:24]

def formatKeyParam(rotation_key):
    if rotation_key[0:8] == 'did:key:':
        return rotation_key

    key_from_file = priv_hex_to_did_key.privHexFileToDidKey(rotation_key)
    if key_from_file is None:
        raise Exception("Key did not look like a did key and was not found as a file: "+rotation_key)
    return key_from_file

def formatKeyParams(rotation_keys):
    ret = []
    for rotation_key in rotation_keys:
        ret.append(formatKeyParam(rotation_key))
    return ret

def formatEndpoint(url):
    if url[:8] != 'https://' and url[:7] != 'http://':
        raise Exception("Endpoint parameter did not look like a URL")
    return url

def formatAlsoKnownAs(urls):
    for url in urls:
        if url[:5] != 'at://':
            raise Exception("Endpoint parameter did not look like an at:// URI")
    return urls

def populateEntry(entry, args, prev_cid):

    entry = copy.deepcopy(entry)

    del entry['sig']
    entry['prev'] = prev_cid

    if args.endpoint is not None:
        entry['services']['atproto_pds']['endpoint'] = formatEndpoint(args.endpoint)
        
    if args.rotationKeys is not None:
        entry['rotationKeys'] = formatKeyParams(args.rotationKeys)
 
    if args.alsoKnownAs is not None:
        entry['alsoKnownAs'] = formatAlsoKnownAs(args.alsoKnownAs)

    if args.verificationMethod is not None:
        entry['verificationMethods']['atproto'] = formatKeyParam(args.verificationMethod)

    if entry['services']['atproto_pds']['endpoint'] is None:
        raise Exception("no pds endpoint would be set")

    if entry['rotationKeys'] is None or len(entry['rotationKeys']) == 0:
        raise Exception("no rotation keys would be set")

    if entry['alsoKnownAs'] is None or len(entry['alsoKnownAs']) == 0:
        raise Exception("no alsoKnownAs would be set")

    if entry['verificationMethods']['atproto'] is None:
        raise Exception("no verification method would be set")

    return entry

if __name__ == '__main__':

    # Start with an empty template
    default_entry = {
        # sig will be added at the end
        "prev": None,
        "type": "plc_operation",
        "services": {
            "atproto_pds": {
                "type":"AtprotoPersonalDataServer",
                "endpoint": None
            }
        },
        "alsoKnownAs": None,
        "rotationKeys": None,
        "verificationMethods": {"atproto": None}
    }

    entry = None

    parser = argparse.ArgumentParser()

    parser.add_argument("--did", help="DID to update (omit for a new DID)")

    parser.add_argument("--prev", help="CID of the entry we will update. (Omit to just use the latest in the directory)")
    parser.add_argument("--prev_idx", type=int, help="--prev but specified by the index of the entry in the history instead of its CID")

    parser.add_argument("--endpoint", help="Endpoint to set (the URL of your PDS)")
    parser.add_argument("--rotationKeys", type=lambda arg: arg.split(','), help="Comma-delimited list of rotation keys to set")
    parser.add_argument("--alsoKnownAs", type=lambda arg: arg.split(','), help="Comma-delimited list of handles (also known as) to set")
    parser.add_argument("--verificationMethod", help="Verification key to set")

    parser.add_argument("--keys", default="./pk", help="Path to directory containing private keys")
    parser.add_argument("--out", help="File name to which to output")
    parser.add_argument("--history", help="Output a full history not just the single entry")

    parser.add_argument("--broadcast", help="broadcast to the specified server eg https://plc.directory")
    args = parser.parse_args()

    param_did = args.did
    param_prev = args.prev

    prev_idx = None
    prev_cid = None

    available_keys = None

    did = args.did
    did_history = []

    relevant_history = []

    if did is None:
        print("No did supplied, trying to create a new entry")
        entry = populateEntry(default_entry, args, None)

        # Genesis is signed with its own keys for no apparent reason
        available_keys = entry['rotationKeys']

    else:
        did_history = loadHistory(did)

        if args.prev is not None:
            prev_cid = args.prev
        else:
            prev_idx = args.prev_idx
            if prev_idx is not None and prev_idx > len(did_history) - 1:
                raise Exception("prev index was not found in history")

        if prev_idx is None and prev_cid is None:
            print("No prev argument supplied, using final entry found in history")
            prev_idx = len(did_history) - 1

        is_entry_found = False
        for i in range(0, len(did_history)):
            did_update = did_history[i]
            
            # Everything is relevant until we reach prev
            relevant_history.append(did_update)

            cid = did_update['cid']

            if did_update['operation']['prev'] is None:
                #print("got genesis")
                #print(did_update)
                calc_did = calculateDid(did_update['operation'])
                #if did == calc_did:
                #    print("dids match (" + calc_did + ")")
                #else:
                #    print("dids mismatch (" + calc_did + " vs " + did + ")")

            # check the cid
            calc_cid = calculateCid(did_update['operation'])
            #if cid == calc_cid:
            #    print("cids match (" + calc_cid + ")")
            #else:
            #    print("cids mismatch (" + calc_cid + " vs " + cid + ")")

            if prev_idx is not None and prev_idx == i:
                prev_cid = cid

            if prev_cid == did_update['cid']:
                is_entry_found = True
                available_keys = did_update['operation']['rotationKeys']
                entry = populateEntry(did_update['operation'], args, prev_cid)
                break

        if not is_entry_found:
            raise Exception("Could not find specified prev in history")

    #print(available_keys)
    priv_hex = None
    for available_key in available_keys:
        priv_hex = priv_hex_to_did_key.privHexForDidKey(available_key, args.keys)
        if priv_hex is not None:
            print("Found the usable key "+available_key)
            break

    if priv_hex is None:
        print("Could not find a key")
        print("Needed one of:")
        print(available_keys)
        exit()

    signed_entry = signUpdate(entry, priv_hex)
    update_cid = calculateCid(signed_entry)

    if did is None:
        did = calculateDid(signed_entry)
        print("Made did:")
        print(did)

    output = []
    if args.history is not None and int(args.history) > 0:
        output = relevant_history

    # We format this like the did audit log so we can check it with the same tooling
    # createdAt is assigned by the directory server when it receives the update
    output.append({
        "did": did,
        "operation": signed_entry,
        "cid": update_cid,
        "nullified": False,
        "createdAt": None
    })

    out_file = args.out
    if out_file is None:
        if not os.path.exists(OUT_DIR):
            os.mkdir(OUT_DIR)
        out_file = OUT_DIR + '/' + did + '-' + update_cid + '.json'

    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=4, sort_keys=False)
        print("Output written to:")
        print(out_file)

    if args.broadcast is not None:
        url = args.broadcast + '/' + did
        print("Submitting to " + url)
        r = requests.post(url, json=signed_entry)
        print("Directory response:")
        print(r.status_code)
