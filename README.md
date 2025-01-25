# Diddums

A simple tool for manipulating atproto DID histories

## You probably shouldn't be using this

This tool was created for doing abhorrent things with the DID history mainly for the purpose of testing, for example making weird forks of the history that shouldn't normally exist. Although in theory it could be used for normal purposes like account migration, you're probably better off using tools designed for that purpose.

In particular take a look at [Goat](https://github.com/bluesky-social/indigo/blob/main/cmd/goat/README.md).

If you're just tinkering around, nothing bad should happen as long as you don't run it with the `--broadcast` flag. But I've barely tested it so YMMV.

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

    python diddums --help

## Private keys

To sign updates to your DID history, you need one of the private keys currently listed in the previous update. You can see these listed in the final entry of your audit log, eg the log for the DID `did:plc:pyzlzqt6b2nyrha7smfry6rv` can be found at [https://plc.directory/did:plc:pyzlzqt6b2nyrha7smfry6rv/log/audit](https://plc.directory/did:plc:pyzlzqt6b2nyrha7smfry6rv/log/audit)

By default Diddums expects them to be in a directory called `pk`.

Private keys are 32 bytes long, or 64 characters when written out in hexadecimal. Each key should be its own file with a single line, prefixed with `0x`. You can generate a new one with something like ``echo "0x `openssl rand -hex 32` " > pk/mykey``.

If you're running your own PDS, you can find the default rotation key used to sign updates of accounts you create on that PDS in the `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX` entry of `/pds/pds.env`. You'll need to add the `0x` to the beginning.

Your own PDS will also store the verification keys (used for signing off on skeets) for its users. These are in places like `/pds/actors/5c/did\:plc\:mtq3e4mgt7wyjhhaniezej67/key`. You can output these as hex with something like `python3 -c "print(open('./key', 'rb').read().hex())"`. Then add the `0x` to the beginning.

Once you've stored your keys in your `pk` directory you can refer to them either by their full name (pubkey) like `did:key:zQ3shrBmk4hva9E1Sdag7jG9up32oJd8DWfv8mHs96ug8abP1` or by the path to the file like `pk/mykey`.

You can get the DID key of a private key by running the accompanying script `priv_hex_to_did_key.py`, eg `python priv_hex_to_did_key.py pk/mykey`.


## Usage

Run `python diddums.py --help` for all the options.

To update an existing DID, run `python diddums.py --did did:plc:something` where `did:plc:something` is the DID you want to update. Pass additional arguments for the things you want to change. Diddums will output the signed entry in a file. If you add the argument `--broadcast https://plc.directory` it will attempt to submit it to the public directory.

Normally you will want to add your entry after the latest one. Diddums will get this automatically from the directory. If you want to update an earlier entry, you can pass the `prev` argument with the CID of the entry you want to update. This is only useful for testing or evil purposes; If you try to send it to the public directory it should reject it.

If you don't supply a DID, Diddums will try to create a new directory entry. This will require you to provide values for all the fields that need to go in the DID.

## Examples (leaving out the `--broadcast` step):

### Set your handle to "my.domain.example.com":

    python diddums.py --did did:plc:ee7kjipyhx3cf6nmh2l5scbl --alsoKnownAs 'at://my.domain.example.com'

Note that (once broadcast) this only updates the DID registry. You need further steps to prove to the world that you own `my.domain.example.com`.

### Set your rotation key to did:key:zQ3shrBmk4hva9E1Sdag7jG9up32oJd8DWfv8mHs96ug8abP1:

    python diddums.py --did did:plc:ee7kjipyhx3cf6nmh2l5scbl --rotationKeys did:key:zQ3shrBmk4hva9E1Sdag7jG9up32oJd8DWfv8mHs96ug8abP1

### Set 3 rotation keys based on keys in files your pk/ directory:

    python diddums.py --did did:plc:ee7kjipyhx3cf6nmh2l5scbl --rotationKeys pk/mykey1,pk/mykey2,pk/mykey3

### Set your verification key to a file in your pk/ directory:

    python diddums.py --did did:plc:ee7kjipyhx3cf6nmh2l5scbl --verificationMethod pk/mySigningKey

Note that this doesn't actually give your PDS the key, so you need extra steps before you can sign with it. (This is the kind of reason you probably should be using Goat instead of Diddums.)

### Change your PDS to mypds.example.com

    python diddums.py --did did:plc:ee7kjipyhx3cf6nmh2l5scbl --endpoint mypds.example.com

Note that this doesn't do anything to make sure you actually have an account on the PDS `mypds.example.com`.
