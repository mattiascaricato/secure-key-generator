# secure-ethereum-private-key-generator ![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
Securely generate cryptographically strong, exportable Ethereum private keys by mixing AWS KMS entropy with the local CSPRNG. Ensures secp256k1 elliptic curve compliance.

- **Entropy mixing**: XORs **AWS KMS** randomness with the local CSPRNG (`secrets`), so neither AWS nor a flawed local RNG alone can determine the key.
- Filters out invalid keys exceeding **secp256k1** elliptic curve limits.
- Simple **script** or **one-liner CLI command**.
- Minimal dependencies: **boto3** and **eth-keys** (the one-liner also uses the **AWS CLI**).

## Threat model
The key is meant to be exported (printed) for use in a wallet, so the goal is strong entropy, not HSM custody:

- AWS only ever sees its half of the entropy. The final key is `KMS_bytes XOR local_bytes`, computed locally — compromising the key requires compromising *both* sources.
- KMS `GenerateRandom` calls are logged in CloudTrail (event metadata only, not the bytes), so your AWS account keeps a timestamped record that a key was generated.
- The key is printed to stdout: run this locally, and mind terminal scrollback, tmux logging, and CI logs.
- If you want a key that never exists outside an HSM instead, use a KMS asymmetric key (`ECC_SECG_P256K1`) and sign inside KMS — different tool, different goal.

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
python3 generate_eth_pk.py
```

## One-liner-command
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
[MIT](https://github.com/mattiascaricato/secure-ethereum-private-key-generator/blob/main/LICENSE)
