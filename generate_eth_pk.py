import boto3
from eth_keys import keys

# Order of secp256k1 (fixed curve parameter)
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Initialize AWS KMS client
kms_client = boto3.client("kms")

def generate_random_32_bytes():
    """Generate 32 random bytes using AWS KMS with boto3."""
    response = kms_client.generate_random(NumberOfBytes=32)
    raw_bytes = response["Plaintext"]

    if not raw_bytes or len(raw_bytes) != 32:
        raise ValueError("Failed to generate valid random bytes from KMS")

    return raw_bytes.hex()

def is_valid_private_key(hex_key):
    """Checks if the private key is within the valid SECP256K1 range: 1 ≤ key < curve order (prevents invalid keys)."""
    key_int = int(hex_key, 16)
    return 1 <= key_int < SECP256K1_ORDER

def main():
    try:
        while True:
            private_key = generate_random_32_bytes()
            if is_valid_private_key(private_key):
                pk = keys.PrivateKey(bytes.fromhex(private_key))
                public_key = pk.public_key
                address = public_key.to_checksum_address()
                print(f"Private Key: {private_key}")
                print(f"Wallet Address: {address}")
                break
    except Exception as e:
        print(f"Error generating wallet: {str(e)}")
        raise

if __name__ == "__main__":
    main()
