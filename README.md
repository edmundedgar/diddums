# Diddums

Edmund Edgar [@goat.navy](https://bsky.app/profile/goat.navy), 2025-01

A simple tool for manipulating atproto DID histories

## You probably shouldn't be using this

This is a simple tool for adding entries to the DID history, and nothing else. Most normal operations also involve setting something other than the DID history, for example adding an account to a PDS or verifying a domain. Consider using a tool like [Goat](https://github.com/bluesky-social/indigo/blob/main/cmd/goat/README.md) that will also handle these other settings and make sure they are consistent with what you are doing to the DID history.

If you're just tinkering around, nothing bad should happen as long as you don't run it with the `--broadcast` flag.

## Installation

Just clone the repo, eg

    git clone https://github.com/edmundedgar/diddums.git

I recommend you use a virtualenv for dependencies, eg

    mkdir -p ~/venv/diddums
    python3 -m venv ~/venv/diddums
    source ~/venv/diddums/bin/activate

Install the requirements

    pip install -r requirements.txt

Now you can run diddums and see the options:

    python diddums.py --help

## Private keys

Private keys are 32 bytes long. Diddums expects to find key you sign with encoded in hexadecimal (so 64 characters) prefixed with `0x`, and stored in its own file containing a single line. You can generate a new one with something like ``echo "0x`openssl rand -hex 32`" > pk/mykey``.

By default Diddums expects them to be in a directory called `pk`.

Keys in the PLC directory are referred to by their pubkeys in [did:key](https://w3c-ccg.github.io/did-method-key/) format. You can find out the did:key pubkey of one of your private keys by running the accompanying script `priv_hex_to_did_key.py`, eg `python priv_hex_to_did_key.py pk/mykey`.

Once you've stored your keys in your `pk` directory you can refer to them either by their full name (pubkey) like `did:key:zQ3shrBmk4hva9E1Sdag7jG9up32oJd8DWfv8mHs96ug8abP1` or by the path to the file like `pk/mykey`.

### Rotation keys

To sign updates to your DID history, you need the private key to one of the rotation keys currently listed in the previous update. You can see these listed in the final entry of your audit log, eg the log for the DID `did:plc:pyzlzqt6b2nyrha7smfry6rv` can be found at [https://plc.directory/did:plc:pyzlzqt6b2nyrha7smfry6rv/log/audit](https://plc.directory/did:plc:pyzlzqt6b2nyrha7smfry6rv/log/audit)

If you're running your own PDS, you can find the default rotation key used to sign updates of accounts you create on that PDS in the `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX` entry of `/pds/pds.env`. You'll need to add the `0x` to the beginning.

### Verification keys

If you're running your own PDS it will also be storing the verification keys (used for signing off on skeets) for its users. These are in places like `/pds/actors/5c/did\:plc\:mtq3e4mgt7wyjhhaniezej67/key`. You can output these as hex with something like `python3 -c "print(open('./key', 'rb').read().hex())"`. Then add the `0x` to the beginning.

You don't sign with these for DID operations, unless you've set your DID to use the same key as a rotation key.

## Usage

Run `python diddums.py --help` for all the options.

To update an existing DID, run `python diddums.py --did did:plc:something` where `did:plc:something` is the DID you want to update. Pass additional arguments for the things you want to change. Diddums will output the signed entry in a file. If you add the argument `--broadcast https://plc.directory` it will attempt to submit it to the public directory.

Normally you will want to add your entry after the latest one. Diddums will get this automatically from the directory. If you want to update an earlier entry, you can pass the `prev` argument with the CID of the entry you want to update. This is only useful for testing or evil purposes; If you try to send it to the public directory it should reject it.

If you don't supply a DID, Diddums will try to create a new directory entry. This will require you to provide values for all the fields that need to go in the DID.

## Examples (leaving out the `--broadcast` step):

### Set your handle to "my.domain.example.com":

    python diddums.py --did did:plc:ee7kjipyhx3cf6nmh2l5scbl --alsoKnownAs 'at://my.domain.example.com'

Note that (once broadcast) this only updates the DID registry. You need further steps to prove to the world that you own `my.domain.example.com`.

### Set your rotation key to the specified did pubkey

    python diddums.py --did did:plc:ee7kjipyhx3cf6nmh2l5scbl --rotationKeys did:key:zQ3shrBmk4hva9E1Sdag7jG9up32oJd8DWfv8mHs96ug8abP1

### Set 3 rotation keys based on keys in files your pk/ directory:

    python diddums.py --did did:plc:ee7kjipyhx3cf6nmh2l5scbl --rotationKeys pk/mykey1,pk/mykey2,pk/mykey3

### Set your verification key to a file in your pk/ directory:

    python diddums.py --did did:plc:ee7kjipyhx3cf6nmh2l5scbl --verificationMethod pk/mySigningKey

Note that this doesn't actually give your PDS the key, so you need extra steps before you can sign with it. (This is the kind of reason you probably should be using Goat instead of Diddums.)

### Change your PDS to mypds.example.com

    python diddums.py --did did:plc:ee7kjipyhx3cf6nmh2l5scbl --endpoint https://mypds.example.com

Note that this doesn't do anything to make sure you actually have an account on the PDS `mypds.example.com`.
