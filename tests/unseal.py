#!/usr/bin/env python3

import argparse
import base64
import hashlib
import io
import json
import struct
import sys
import tarfile
from pathlib import Path

import nacl.bindings
import nacl.signing
from Cryptodome.Cipher import AES, PKCS1_OAEP, ChaCha20_Poly1305
from Cryptodome.Hash import SHA256, BLAKE2b
from Cryptodome.IO import PEM
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss

XCHACHA20_POLY1305_NONCE_SIZE = 24
XCHACHA20_POLY1305_TAG_SIZE = 16
XCHACHA20_POLY1305_OVERHEAD = XCHACHA20_POLY1305_NONCE_SIZE + XCHACHA20_POLY1305_TAG_SIZE

AES_GCM_NONCE_SIZE = 12
AES_GCM_TAG_SIZE = 16
AES_GCM_OVERHEAD = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE

ED25519_SIGNATURE_SIZE = 64
RSA_SIGNATURE_SIZE = int(4096 / 8)

# NOTE: by default, the PSS implementation in Go uses a salt size
# that's dynamically generated, so this might break.
PSS_SALT_SIZE = 446


def load_keys(path):
    key = json.loads(base64.b64decode(path.read_text()))

    nacl_sign_bytes = base64.b64decode(key["NaCl"]["Sign"])
    nacl_sign_seed = nacl.bindings.crypto_sign_ed25519_sk_to_seed(nacl_sign_bytes)
    nacl_sign_key = nacl.signing.SigningKey(nacl_sign_seed).verify_key

    nacl_enc_bytes = base64.b64decode(key["NaCl"]["Encrypt"])
    nacl_enc_priv = nacl.public.PrivateKey(nacl_enc_bytes)
    nacl_enc_key = nacl.public.SealedBox(nacl_enc_priv)

    rsa_sign_key = RSA.import_key(base64.b64decode(key["RSA"]["Sign"]))
    rsa_sign_der = rsa_sign_key.public_key().export_key(format="DER")

    rsa_enc_key = RSA.import_key(base64.b64decode(key["RSA"]["Encrypt"]))
    rsa_enc_der = rsa_enc_key.public_key().export_key(format="DER")

    fingerprints = b"".join([
        base64.b64encode(
            hashlib.sha256(nacl_sign_key.encode()).digest() +
            hashlib.blake2s(nacl_sign_key.encode()).digest()
        ),
        base64.b64encode(
            hashlib.sha256(nacl_enc_priv.public_key.encode()).digest() +
            hashlib.blake2s(nacl_enc_priv.public_key.encode()).digest()
        ),
        base64.b64encode(
            hashlib.sha256(rsa_sign_der).digest() +
            hashlib.blake2s(rsa_sign_der).digest()
        ),
        base64.b64encode(
            hashlib.sha256(rsa_enc_der).digest() +
            hashlib.blake2s(rsa_enc_der).digest()
        ),
    ])
    fingerprint = base64.b64encode(
        hashlib.sha256(fingerprints).digest() + hashlib.blake2s(fingerprints).digest()
    ).decode()

    return nacl_sign_key, nacl_enc_key, rsa_sign_key, rsa_enc_key, fingerprint


def decrypt(src, privkey, encrypted):
    nacl_sign_key, nacl_enc_key, rsa_sign_key, rsa_enc_key, fingerprint = load_keys(privkey)

    with open(src, "rb") as f:
        #
        # 1. Read and verify metadata signatures with NaCl and RSA.
        #
        metadata_size = struct.unpack(">I", f.read(struct.calcsize(">I")))[0]
        metadata_bytes = f.read(metadata_size)

        nacl_signature = f.read(ED25519_SIGNATURE_SIZE)
        nacl_sign_key.verify(metadata_bytes, nacl_signature)

        rsa_signature = f.read(RSA_SIGNATURE_SIZE)
        rsa_hash = BLAKE2b.new(digest_bits=512, data=metadata_bytes)
        rsa_pss = pss.new(rsa_sign_key.public_key(), salt_bytes=PSS_SALT_SIZE)
        rsa_pss.verify(rsa_hash, rsa_signature)

        metadata = json.loads(metadata_bytes)

        #
        # 2. Read blob.
        #
        blob = f.read()

        #
        # 3. Verify the blob with digests from the metadata that was
        #    verified in #1.
        #
        sha256 = base64.b64encode(hashlib.sha256(blob).digest()).decode()
        if sha256 != metadata["Hashes"]["SHA256"]:
            raise RuntimeError("bad digest")

        keccak512 = base64.b64encode(hashlib.sha3_512(blob).digest()).decode()
        if keccak512 != metadata["Hashes"]["KECCAK512"]:
            raise RuntimeError("bad digest")

        blake2b = base64.b64encode(hashlib.blake2b(blob).digest()).decode()
        if blake2b != metadata["Hashes"]["BLAKE2b512"]:
            raise RuntimeError("bad digest")

        plaintext = []
        if encrypted:
            #
            # 4. Decrypt the blob in chunks.  Each chunk is encrypted with
            #    XChaCha20Poly1305 (outer layer) and AES256-GCM (inner layer).
            #    The ephemeral keys for XChaCha20Poly1305 and AES256-GCM are
            #    stored encrypted with NaCl (outer layer) and RSA (inner
            #    layer) in the metadata file that was verified in #1.
            #
            rsa_oaep = PKCS1_OAEP.new(rsa_enc_key, SHA256)

            xcp_key_data = metadata["Keys"][fingerprint]["XChaCha20Poly1305"]
            xcp_key_partial = rsa_oaep.decrypt(base64.b64decode(xcp_key_data))
            xcp_key = nacl_enc_key.decrypt(base64.b64decode(xcp_key_partial))

            aes_key_data = metadata["Keys"][fingerprint]["AESGCM"]
            aes_key_partial = rsa_oaep.decrypt(base64.b64decode(aes_key_data))
            aes_key = nacl_enc_key.decrypt(base64.b64decode(aes_key_partial))

            tmp = blob
            chunk_size = metadata["ChunkSize"] + XCHACHA20_POLY1305_OVERHEAD + AES_GCM_OVERHEAD
            while data := tmp[:chunk_size]:
                xcp_nonce = data[:XCHACHA20_POLY1305_NONCE_SIZE]
                xcp_tag = data[-XCHACHA20_POLY1305_TAG_SIZE:]
                xcp_ciphertext = data[XCHACHA20_POLY1305_NONCE_SIZE:-XCHACHA20_POLY1305_TAG_SIZE]
                xcp = ChaCha20_Poly1305.new(key=xcp_key, nonce=xcp_nonce)
                partial = xcp.decrypt_and_verify(xcp_ciphertext, xcp_tag)

                aes_nonce = partial[:AES_GCM_NONCE_SIZE]
                aes_tag = partial[-AES_GCM_TAG_SIZE:]
                aes_ciphertext = partial[AES_GCM_NONCE_SIZE:-AES_GCM_TAG_SIZE]
                aes = AES.new(
                    key=aes_key,
                    mode=AES.MODE_GCM,
                    nonce=aes_nonce,
                )
                plaintext.append(aes.decrypt_and_verify(aes_ciphertext, aes_tag))

                tmp = tmp[chunk_size:]
        else:
            #
            # 4. If the blob is signed but not encrypted, use it as-is.
            #
            plaintext.append(blob)

        #
        # 5. Return the plaintext.
        #
        return io.BytesIO(b"".join(plaintext))


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("-k", "--privkey", type=Path, required=True)
    ap.add_argument("-i", "--in", type=Path, required=True, dest="src")
    ap.add_argument("--signed-only", action="store_true")
    ap.add_argument("--tar", action="store_true")
    return ap.parse_args()


def main():
    args = parse_args()
    plaintext = decrypt(args.src, args.privkey, not args.signed_only)

    content = []
    if args.tar:
        with tarfile.TarFile(fileobj=plaintext) as t:
            for member in t.getmembers():
                if not member.isdir():
                    data = t.extractfile(member).read()
                    content.append({
                        "path": member.path,
                        "data": base64.b64encode(data).decode(),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    })
    else:
        data = plaintext.read()
        content.append({
            "path": "",
            "data": base64.b64encode(data).decode(),
            "sha256": hashlib.sha256(data).hexdigest(),
        })

    print(json.dumps(content, indent=2))


if __name__ == "__main__":
    main()
