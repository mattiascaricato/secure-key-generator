import argparse
import secrets

import boto3
from eth_keys import keys
from mnemonic import Mnemonic

# Order of secp256k1 (fixed curve parameter)
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Initialize AWS KMS client
kms_client = boto3.client("kms")

def generate_entropy():
    """Generate 32 entropy bytes by XOR-mixing AWS KMS entropy with the local CSPRNG.

    The result is at least as strong as the strongest of the two sources, so
    neither AWS nor a flawed local RNG alone can determine the secret.
    """
    kms_bytes = kms_client.generate_random(NumberOfBytes=32)["Plaintext"]

    if not kms_bytes or len(kms_bytes) != 32:
        raise ValueError("Failed to generate valid random bytes from KMS")

    local_bytes = secrets.token_bytes(32)
    return bytes(a ^ b for a, b in zip(kms_bytes, local_bytes))

def is_valid_private_key(key_bytes):
    """Checks if the private key is within the valid SECP256K1 range: 1 ≤ key < curve order (prevents invalid keys)."""
    key_int = int.from_bytes(key_bytes, "big")
    return 1 <= key_int < SECP256K1_ORDER

def generate_seed_phrase():
    """Generate a 24-word BIP-39 mnemonic (256 bits of mixed entropy)."""
    words = Mnemonic("english").to_mnemonic(generate_entropy())
    print(f"Seed Phrase: {words}")

def generate_private_key():
    """Generate a standalone secp256k1 private key and its Ethereum address."""
    while True:
        key_bytes = generate_entropy()
        if is_valid_private_key(key_bytes):
            pk = keys.PrivateKey(key_bytes)
            address = pk.public_key.to_checksum_address()
            print(f"Private Key: {key_bytes.hex()}")
            print(f"Wallet Address: {address}")
            break

def main():
    parser = argparse.ArgumentParser(description="Generate a BIP-39 seed phrase or a secp256k1 private key from KMS+local mixed entropy.")
    parser.add_argument("--pk", action="store_true", help="generate a raw secp256k1 private key instead of a seed phrase")
    args = parser.parse_args()

    if args.pk:
        generate_private_key()
    else:
        generate_seed_phrase()

if __name__ == "__main__":
    main()
