import argparse
import hashlib
import secrets
import sys
import time

try:
    import termios
    import tty
except ImportError:  # non-Unix: keyboard mode unavailable, dice mode still works
    termios = tty = None

from eth_keys import keys
from mnemonic import Mnemonic

# Order of secp256k1 (fixed curve parameter)
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# log2(6) ≈ 2.58 bits per d6 roll → 100 rolls ≥ 256 bits
MIN_DICE_ROLLS = 100
MIN_KEYSTROKES = 100

def collect_dice_entropy():
    """Collect ≥100 physical d6 rolls and hash them into 32 bytes."""
    print(f"Roll a physical d6 and type the results ({MIN_DICE_ROLLS}+ rolls, digits 1-6, spaces ok).")
    print("Press Enter between batches; the counter shows progress.")
    rolls = ""
    while len(rolls) < MIN_DICE_ROLLS:
        line = input(f"[{len(rolls)}/{MIN_DICE_ROLLS}] > ").replace(" ", "").strip()
        if not line:
            continue
        if not set(line) <= set("123456"):
            print("Only digits 1-6.")
            continue
        rolls += line
    return hashlib.sha256(rolls.encode()).digest()

def collect_keyboard_entropy():
    """Collect keystroke timing jitter: 100 keypresses, hashed with their nanosecond timestamps."""
    print(f"Mash the keyboard randomly, varying rhythm, until the counter completes ({MIN_KEYSTROKES} keystrokes).")
    samples = []
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        for i in range(MIN_KEYSTROKES):
            ch = sys.stdin.read(1)
            if not ch:
                raise EOFError("stdin closed during keystroke collection")
            samples.append(f"{ch!r}:{time.perf_counter_ns()}")
            print(f"\r  {i + 1}/{MIN_KEYSTROKES}", end="", flush=True)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    print()
    return hashlib.sha256("|".join(samples).encode()).digest()

def choose_entropy_source():
    """Prompt for the second entropy source and collect it."""
    print("Second entropy source to mix with the OS CSPRNG:")
    print("  1) dice rolls (recommended, provable entropy)")
    print("  2) keyboard mashing (no props, entropy not provable)")
    while True:
        choice = input("Choice [1/2]: ").strip()
        if choice == "1":
            return collect_dice_entropy()
        if choice == "2":
            if termios is None:
                print("Keyboard mode needs a Unix terminal; use dice rolls.")
                continue
            return collect_keyboard_entropy()
        print("Type 1 or 2.")

def mix_entropy(user_bytes):
    """XOR the user-collected 32 bytes with the OS CSPRNG. The result is at least
    as strong as the strongest of the two sources, so a flawed kernel RNG and
    weak dice/keystrokes must BOTH happen to weaken the secret."""
    if len(user_bytes) != 32:
        raise ValueError(f"user entropy must be 32 bytes, got {len(user_bytes)}")
    return bytes(a ^ b for a, b in zip(user_bytes, secrets.token_bytes(32)))

def is_valid_private_key(key_bytes):
    """Checks if the private key is within the valid SECP256K1 range: 1 ≤ key < curve order (prevents invalid keys)."""
    key_int = int.from_bytes(key_bytes, "big")
    return 1 <= key_int < SECP256K1_ORDER

def generate_seed_phrase(user_bytes):
    """Generate a 24-word BIP-39 mnemonic (256 bits of mixed entropy)."""
    words = Mnemonic("english").to_mnemonic(mix_entropy(user_bytes))
    print(f"Seed Phrase: {words}")

def generate_private_key(user_bytes):
    """Generate a standalone secp256k1 private key and its Ethereum address."""
    while True:
        key_bytes = mix_entropy(user_bytes)
        if is_valid_private_key(key_bytes):
            pk = keys.PrivateKey(key_bytes)
            address = pk.public_key.to_checksum_address()
            print(f"Private Key: {key_bytes.hex()}")
            print(f"Wallet Address: {address}")
            break

def main():
    parser = argparse.ArgumentParser(description="Generate a BIP-39 seed phrase or a secp256k1 private key from OS CSPRNG entropy mixed with dice rolls or keystroke timing.")
    parser.add_argument("--pk", action="store_true", help="generate a raw secp256k1 private key instead of a seed phrase")
    args = parser.parse_args()

    try:
        user_bytes = choose_entropy_source()
        if args.pk:
            generate_private_key(user_bytes)
        else:
            generate_seed_phrase(user_bytes)
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.")
        sys.exit(1)

if __name__ == "__main__":
    main()
