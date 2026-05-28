"""Crypt4GH header re-encryption utilities.

The re-encryptor service uses this module to transform an existing crypt4gh
header so it can be decrypted by a different recipient key.
"""

import io

import crypt4gh.header


def reencrypt_header(
    original_header_bytes: bytes,
    sender_private_key: bytes,
    recipient_public_key: bytes,
) -> bytes:
    """Re-encrypt a crypt4gh header from sender to recipient.

    Decrypts session-key packets with *sender_private_key*, then encrypts them
    so only *recipient_public_key* can recover them.
    """
    import nacl.public as nacl_pub

    stream = io.BytesIO(original_header_bytes)
    parsed = crypt4gh.header.parse(stream)
    if isinstance(parsed, tuple):
        _magic, _version, packets = parsed
    else:
        packets = list(parsed)

    # Ephemeral sender key for the re-encrypted header
    ephemeral_sk_obj = nacl_pub.PrivateKey.generate()
    ephemeral_sk = bytes(ephemeral_sk_obj)

    sender_key = (0, sender_private_key, None)
    recipient_keys = [(0, ephemeral_sk, recipient_public_key)]

    new_packets = crypt4gh.header.reencrypt(
        packets,
        keys=[sender_key],
        recipient_keys=recipient_keys,
    )
    return crypt4gh.header.serialize(new_packets)
