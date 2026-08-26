import secrets

import boto3
from eth_keys import keys

# Order of secp256k1 (fixed curve parameter)
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Initialize AWS KMS client
kms_client = boto3.client("kms")

def generate_key_bytes():
    """Generate 32 key bytes by XOR-mixing AWS KMS entropy with the local CSPRNG.

    The result is at least as strong as the strongest of the two sources, so
    neither AWS nor a flawed local RNG alone can determine the key.
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

def main():
    while True:
        key_bytes = generate_key_bytes()
        if is_valid_private_key(key_bytes):
            pk = keys.PrivateKey(key_bytes)
            address = pk.public_key.to_checksum_address()
            print(f"Private Key: {key_bytes.hex()}")
            print(f"Wallet Address: {address}")
            break

if __name__ == "__main__":
    main()
