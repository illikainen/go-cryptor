#!/usr/bin/env python3

import argparse
import base64
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

import nacl.bindings
import nacl.signing
from Cryptodome.Cipher import AES, PKCS1_OAEP, ChaCha20_Poly1305
from Cryptodome.Hash import SHA256, BLAKE2b
from Cryptodome.IO import PEM
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss

METADATA_SIZE = 1024 * 8
XCHACHA20_POLY1305_NONCE_SIZE = 24
AES_GCM_NONCE_SIZE = 12
ED25519_SIGNATURE_SIZE = 64
RSA_SIGNATURE_SIZE = int(4096 / 8)

# NOTE: by default, the PSS implementation in Go uses a salt size
# that's dynamically generated, so this might break.
PSS_SALT_SIZE = 446


def read_key(lines):
    if not lines[0].startswith("-----BEGIN"):
        raise RuntimeError("bad key")

    key = []
    for i, line in enumerate(lines):
        key.append(line)
        if line.startswith("-----END"):
            break

    return "\n".join(key), lines[i + 1:]


def load_keys(path):
    lines = path.read_text().splitlines()

    nacl_sign_pem, rest = read_key(lines)
    nacl_sign_bytes, *_ = PEM.decode(nacl_sign_pem)
    nacl_sign_seed = nacl.bindings.crypto_sign_ed25519_sk_to_seed(nacl_sign_bytes)
    nacl_sign_key = nacl.signing.SigningKey(nacl_sign_seed).verify_key

    nacl_enc_pem, rest = read_key(rest)
    nacl_enc_bytes, *_ = PEM.decode(nacl_enc_pem)
    nacl_enc_priv = nacl.public.PrivateKey(nacl_enc_bytes)
    nacl_enc_key = nacl.public.SealedBox(nacl_enc_priv)

    rsa_sign_pem, rest = read_key(rest)
    rsa_sign_key = RSA.import_key(rsa_sign_pem)
    rsa_sign_der = rsa_sign_key.public_key().export_key(format="DER")

    rsa_enc_pem, rest = read_key(rest)
    rsa_enc_key = RSA.import_key(rsa_enc_pem)
    rsa_enc_der = rsa_enc_key.public_key().export_key(format="DER")

    if rest:
        sys.exit("bad key")

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
    fingerprint = "NaCl+RSA:" + base64.b64encode(
        hashlib.sha256(fingerprints).digest() + hashlib.blake2s(fingerprints).digest()
    ).decode()

    return nacl_sign_key, nacl_enc_key, rsa_sign_key, rsa_enc_key, fingerprint


def decrypt(src, privkey):
    nacl_sign_key, nacl_enc_key, rsa_sign_key, rsa_enc_key, fingerprint = load_keys(privkey)

    with open(src, "rb") as f:
        #
        # 1. Read and verify metadata signatures with NaCl and RSA.
        #
        metadata_bytes = f.read(METADATA_SIZE)

        nacl_signature = f.read(ED25519_SIGNATURE_SIZE)
        nacl_sign_key.verify(metadata_bytes, nacl_signature)

        rsa_signature = f.read(RSA_SIGNATURE_SIZE)
        rsa_hash = BLAKE2b.new(digest_bits=512, data=metadata_bytes)
        rsa_pss = pss.new(rsa_sign_key.public_key(), salt_bytes=PSS_SALT_SIZE)
        rsa_pss.verify(rsa_hash, rsa_signature)

        metadata = json.loads(metadata_bytes.rstrip(b"\x00"))

        #
        # 2. Read encrypted blob.
        #
        blob = f.read()

        #
        # 3. Verify the encrypted blob with digests from the metadata
        #    that was verified in #1.
        #
        sha256 = hashlib.sha256(blob).hexdigest()
        if sha256 != metadata["Hashes"]["SHA256"]:
            raise RuntimeError("bad digest")

        keccak512 = hashlib.sha3_512(blob).hexdigest()
        if keccak512 != metadata["Hashes"]["KECCAK512"]:
            raise RuntimeError("bad digest")

        blake2b = hashlib.blake2b(blob).hexdigest()
        if blake2b != metadata["Hashes"]["BLAKE2b512"]:
            raise RuntimeError("bad digest")

        #
        # 4. Decrypt the inner layer of the blob with XChaCha20Poly1305.
        #    The ephemeral key for XChaCha20Poly1305 is stored encrypted
        #    with RSA and NaCl in the metadata file that was verified in
        #    #1.
        #
        partial_plaintext = []
        rsa_oaep = PKCS1_OAEP.new(rsa_enc_key, SHA256)

        xcp_key_data = metadata["Keys"][fingerprint + ":XChaCha20Poly1305"]
        xcp_key_partial = rsa_oaep.decrypt(base64.b64decode(xcp_key_data))
        xcp_key = json.loads(nacl_enc_key.decrypt(base64.b64decode(xcp_key_partial)))

        tmp = blob
        while data := tmp[:xcp_key["ChunkSize"]]:
            nonce = data[:XCHACHA20_POLY1305_NONCE_SIZE]
            ciphertext = data[XCHACHA20_POLY1305_NONCE_SIZE:]

            xcp = ChaCha20_Poly1305.new(key=base64.b64decode(xcp_key["Key"]), nonce=nonce)
            partial_plaintext.append(xcp.decrypt(ciphertext))
            tmp = tmp[xcp_key["ChunkSize"]:]

        #
        # 5. Decrypt the outer layer of the blob with AES-GCM.  The
        #    ephemeral key for AES-GCM is stored encrypted with RSA and
        #    NaCl in the metadata file that was verified in #1.
        #
        plaintext = []

        aes_key_data = metadata["Keys"][fingerprint + ":AESGCM"]
        aes_key_partial = rsa_oaep.decrypt(base64.b64decode(aes_key_data))
        aes_key = json.loads(nacl_enc_key.decrypt(base64.b64decode(aes_key_partial)))

        tmp = b"".join(partial_plaintext)
        while data := tmp[:aes_key["ChunkSize"]]:
            nonce = data[:AES_GCM_NONCE_SIZE]
            ciphertext = data[AES_GCM_NONCE_SIZE:]

            aes = AES.new(
                key=base64.b64decode(aes_key["Key"]),
                mode=AES.MODE_GCM,
                nonce=nonce,
            )
            plaintext.append(aes.decrypt(ciphertext))
            tmp = tmp[aes_key["ChunkSize"]:]

        #
        # 6. Return the plaintext archive.
        #
        return zipfile.ZipFile(io.BytesIO(b"".join(plaintext)))


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("-k", "--privkey", type=Path, required=True)
    ap.add_argument("-i", "--in", type=Path, required=True, dest="src")
    return ap.parse_args()


def main():
    args = parse_args()
    content = []
    with decrypt(args.src, args.privkey) as z:
        for name in z.namelist():
            with z.open(name) as f:
                data = f.read()
                content.append({
                    "path": name,
                    "data": data.decode(),
                    "sha256": hashlib.sha256(data).hexdigest(),
                })
    print(json.dumps(content, indent=2))


if __name__ == "__main__":
    main()
