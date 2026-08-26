# secure-key-generator ![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
A BIP-39 seed phrase generator and crypto private key generator with strong, exportable entropy: AWS KMS randomness XOR-mixed with the local CSPRNG. Two modes: a 24-word BIP-39 mnemonic (importable by any wallet on Ethereum, Bitcoin, Solana, or any BIP39/BIP32 chain) or a raw secp256k1 private key.

- **Entropy mixing**: the secret is `KMS_bytes XOR local_bytes`, computed locally. Neither AWS nor a flawed local RNG alone can determine it.
- **Seed phrase mode (default)**: 24-word BIP-39 mnemonic, 256 bits of entropy. Works with Ethereum, Bitcoin, Solana, or anything that speaks BIP-39/BIP-32.
- **Private key mode (`--pk`)**: standalone secp256k1 key, validated against the curve order, with its Ethereum checksum address.
- Minimal dependencies: boto3, eth-keys, mnemonic.

## Threat model
The output is meant to be exported (printed) for use in a wallet, so the goal is strong entropy:

- AWS only ever sees its half of the entropy. Compromising the secret requires compromising both sources.
- KMS `GenerateRandom` calls are logged in CloudTrail (event metadata only, not the bytes), so your AWS account keeps a timestamped record that a secret was generated.
- The secret is printed to stdout. Run this locally, and mind terminal scrollback, tmux logging, and CI logs.

## Requirements
- AWS credentials configured
- Python 3
- AWS CLI (one-liner only)

## Dependencies
```sh
pip3 install -r requirements.txt
```

## Usage
```sh
# 24-word BIP-39 seed phrase (default)
python3 generate_key.py

# raw secp256k1 private key + Ethereum address
python3 generate_key.py --pk
```

## One-liner (private key mode)
The KMS bytes are piped via stdin (never passed as a command-line argument, which would be visible to other processes via `ps`) and mixed with local entropy in-process:

```sh
aws kms generate-random --number-of-bytes 32 --query Plaintext --output text | python3 -c "
import sys, base64, secrets
from eth_keys import keys
kms = base64.b64decode(sys.stdin.read())
assert len(kms) == 32
key = bytes(a ^ b for a, b in zip(kms, secrets.token_bytes(32)))
assert 1 <= int.from_bytes(key, 'big') < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
pk = keys.PrivateKey(key)
print('Private Key:', key.hex())
print('Wallet Address:', pk.public_key.to_checksum_address())
"
```

(The range assert fails with probability ~2⁻¹²⁸; just rerun if you ever hit it.)

## License
[MIT](https://github.com/mattiascaricato/secure-key-generator/blob/main/LICENSE)
