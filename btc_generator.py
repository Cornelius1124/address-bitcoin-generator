import os
import hashlib
import base58
from ecdsa import SigningKey, SECP256k1

# 1. Generate private key (32 bytes)
private_key = os.urandom(32)
private_key_hex = private_key.hex()
print(f"Private key (hex): {private_key_hex}")

# 2. Generate public key
sk = SigningKey.from_string(private_key, curve=SECP256k1)
vk = sk.verifying_key
public_key_bytes = b'\x04' + vk.to_string()  # uncompressed public key

# 3. Perform SHA-256
sha256_pubkey = hashlib.sha256(public_key_bytes).digest()

# 4. Perform RIPEMD-160
ripemd160 = hashlib.new('ripemd160')
ripemd160.update(sha256_pubkey)
pubkey_hash = ripemd160.digest()

# 5. Add version byte (0x00 for mainnet)
versioned_payload = b'\x00' + pubkey_hash

# 6. Calculate checksum
checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]

# 7. Concatenate and encode in Base58Check
address_bytes = versioned_payload + checksum
bitcoin_address = base58.b58encode(address_bytes)

print(f"Bitcoin address: {bitcoin_address.decode()}")
input("\nPress Enter to exit...")
