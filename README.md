# secure-key-generator ![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
A BIP-39 seed phrase generator and crypto private key generator with strong, exportable entropy: the OS CSPRNG XOR-mixed with physical dice rolls or keystroke timing. Fully offline, air-gap friendly. Two modes: a 24-word BIP-39 mnemonic (importable by any wallet on Ethereum, Bitcoin, Solana, or any BIP39/BIP32 chain) or a raw secp256k1 private key.

- **Entropy mixing**: the secret is `os_bytes XOR SHA256(your_input)`, computed locally. Neither a flawed kernel RNG nor weak rolls alone can determine it.
- **Physical second source**: ~100 d6 rolls (provable entropy) or keyboard mashing (no props). The script prompts you to pick.
- **Seed phrase mode (default)**: 24-word BIP-39 mnemonic, 256 bits of entropy.
- **Private key mode (`--pk`)**: standalone secp256k1 key, validated against the curve order, with its Ethereum checksum address.
- **No network, no cloud, no accounts.** Runs on an air-gapped machine.
- Minimal dependencies: eth-keys, mnemonic.

## Why mix entropy
Key generators usually trust a single source of randomness, and local RNGs have failed in the real world: Debian's OpenSSL bug (2008) shipped keys with 15 bits of effective entropy for two years, and Android's SecureRandom flaw (2013) led to actual Bitcoin thefts from wallets generated on-device.

Mixing fixes the single point of failure. XOR-ing two independent sources means the result is at least as strong as the strongest one. To determine the key, an attacker needs to compromise the kernel CSPRNG *and* predict your dice rolls at the same time. The second source is physical on purpose: dice live outside the software supply chain, where no bug or backdoor can reach them.

Practical notes:

- Dice rolls give provable entropy: 100 d6 rolls carry more than the 256 bits the key needs. Keyboard mashing is the propless fallback; its entropy is real but not quantifiable.
- Everything runs offline. No network calls, no cloud account, no audit trail that a secret was generated.
- The secret is printed to stdout. Run this locally, and mind terminal scrollback, tmux logging, and CI logs.
- No mixing scheme survives a compromised machine: whatever computes the key sees the key. For large amounts, generate on a clean, offline machine.

## How it works
```
 dice rolls / keystroke timings      OS CSPRNG secrets.token_bytes
            |                                  |
         SHA-256                           (32 bytes)
        (32 bytes)                             |
            +-------------- XOR --------------+
                             |
                      32 mixed bytes
                             |
            +----------------+----------------+
            |                                 |
     BIP-39 encode                 range check 1 <= k < n
     (SHA-256 checksum)            (secp256k1 curve order)
            |                                 |
    24-word seed phrase          private key + ETH address
```

Both modes draw from the same mixed 256 bits. Your rolls are collected once; in private key mode, keys outside the valid secp256k1 range are rejected and re-mixed with fresh OS bytes (probability ~2^-128, so effectively never).

## Requirements
- Python 3 (Unix terminal; keyboard mode uses termios)

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

The script asks for your second entropy source, then collects it:

```
Second entropy source to mix with the OS CSPRNG:
  1) dice rolls (recommended, provable entropy)
  2) keyboard mashing (no props, entropy not provable)
Choice [1/2]: 1
Roll a physical d6 and type the results (100+ rolls, digits 1-6, spaces ok).
[0/100] > 4526 1355 2641 ...
```

## Disclaimer
This is a small script, not an audited product. Read the code before trusting it with real funds. Whoever has the seed phrase or private key controls the funds, and the output is printed in plaintext. Use at your own risk.

## License
[MIT](https://github.com/mattiascaricato/secure-key-generator/blob/main/LICENSE)
