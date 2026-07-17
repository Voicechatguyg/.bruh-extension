from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16


def encrypt_payload(payload: bytes, key: bytes):
    if len(key) != KEY_SIZE:
        raise ValueError("key must be 32 bytes")

    nonce = os.urandom(NONCE_SIZE)

    aes = AESGCM(key)

    encrypted = aes.encrypt(
        nonce,
        payload,
        None
    )

    ciphertext = encrypted[:-TAG_SIZE]
    auth_tag = encrypted[-TAG_SIZE:]

    return nonce, ciphertext, auth_tag


def decrypt_payload(ciphertext, nonce, auth_tag, key):
    if len(key) != KEY_SIZE:
        raise ValueError("key must be 32 bytes")

    aes = AESGCM(key)

    return aes.decrypt(
        nonce,
        ciphertext + auth_tag,
        None
    )


# --- test -------------------------------------------------------

key = b"12345678901234567890123456789012"

message = b"hello from .bruh v0.3"

print("original:")
print(message)

nonce, ciphertext, tag = encrypt_payload(
    message,
    key
)

print("\nencrypted:")
print(ciphertext)

decrypted = decrypt_payload(
    ciphertext,
    nonce,
    tag,
    key
)

print("\ndecrypted:")
print(decrypted)