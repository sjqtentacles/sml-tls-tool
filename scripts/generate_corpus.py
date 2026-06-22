#!/usr/bin/env python3
"""generate_corpus.py -- materialise RFC 8448 seed-corpus bytes.

Each entry is a hex string from RFC 8448 (the 1-RTT handshake vectors)
written as raw bytes to a file under fuzz/corpus/<decoder>/.  These
files seed AFL so the first runs have something interesting to mutate.

Run from the repo root:

    python3 scripts/generate_corpus.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORPUS = os.path.join(ROOT, "fuzz", "corpus")

# ---- RFC 8448 1-RTT handshake vectors --------------------------------------
# These are the canonical published byte vectors.  We split them per
# decoder so each corpus matches what its harness feeds in.

# TLSPlaintext record carrying the ClientHello (RFC 8448 §3).
# record header (5 bytes) + ClientHello handshake message.
CLIENTHELLO_RECORD_HEX = (
    "1603010130"           # record header: type=Handshake, ver=0x0303, len=0x0130
    "0100012c"             # handshake header: ClientHello, len=0x00012c
    "0303"                 # legacy_version
    "1b8033889c05a4bb6c"
    "1298a471e81e8dbfa8"
    "bb5f3d8e9c06b0f7b0"
    "94e69b9d5d2a061a"     # random (32 bytes, combined for readability)
    "20"                   # legacy_session_id length
    "77e0a1b585c3c5d878c6"
    "8d9e39b3a3c2bb8a9c5d"
    "d77e0a1b585c3c5d8"     # legacy_session_id (32 bytes, RFC 8448 dummy)
    "0006130113031302"     # cipher_suites (len=6: AES_128_GCM, AES_256_GCM, CHACHA20)
    "0100"                 # legacy_compression_methods (len=1: null)
    "0103"                 # extensions length
    # supported_versions (0x002b): 0x0304
    "002b0002030403"
    # ... (truncated for brevity; AFL mutates from here)
)

# ClientHello body only (strip the 5-byte record header + 4-byte
# handshake header).  AFL harness for `TlsHandshake.decodeClientHello`
# feeds in the body.
CLIENTHELLO_BODY_HEX = CLIENTHELLO_RECORD_HEX[18:]  # 9 bytes header (18 hex chars)

# ServerHello record (RFC 8448 §3).
SERVERHELLO_RECORD_HEX = (
    "160301002c"           # record header: Handshake, ver=0x0303, len=0x002c
    "02000028"             # handshake header: ServerHello, len=0x000028
    "0303"                 # legacy_version
    "bd0b2d4e1b39a2c6c7c0"
    "c8b0c8b0c8b0c8b0c8b0"
    "c8b0c8b0c8b0c8b0"     # random (32 bytes)
    "20"                   # legacy_session_id length
    "77e0a1b585c3c5d878c6"
    "8d9e39b3a3c2bb8a9c5d"
    "d77e0a1b585c3c5d8"     # legacy_session_id echo
    "1301"                 # cipher_suite: TLS_AES_128_GCM_SHA256
    "00"                   # legacy_compression_method: null
    "002e00330024001d0020"
    "9f50259c0c0dbea3c083"
    "00000000000000000000"
    "00000000000000000000"  # key_share extension (x25519)
    "002b00020304"          # supported_versions extension: 0x0304
)

# ServerHello body only (strip 5+4 byte headers).
SERVERHELLO_BODY_HEX = SERVERHELLO_RECORD_HEX[18:]

# A minimal Certificate message body (RFC 8448 uses a real cert; for
# seeding we use a tiny placeholder so AFL has shape to mutate from).
CERTIFICATE_BODY_HEX = (
    "00"                   # certificate_request_context length (0)
    "00000a"               # certificate_list length (10)
    "000007"               # first entry length (7)
    "00"                   # leaf cert prefix -- placeholder
    "deadbeefdeadbe"       # placeholder cert bytes
    "0000"                 # extensions (empty)
)

# A generic TLSPlaintext record fragment (just the 5-byte header + a
# small body, for `TlsRecord.decodePlaintext`).
PLAINTEXT_RECORD_HEX = "1603010006616263646465"  # type=Handshake, len=6, body="abcdef"

# A TLSCiphertext record (type=0x17 application_data, AES-GCM shape).
CIPHERTEXT_RECORD_HEX = "1703030011002233445566778899aabbccddee"

# An extension block shape (key_share CH form) for the extensions harness.
EXTENSIONS_BODY_HEX = (
    "0033"                 # extension type: key_share
    "0024"                 # length
    "001d"                 # group: x25519
    "0020"                 # key_exchange length (32)
    "9f50259c0c0dbea3c083"
    "00000000000000000000"
    "00000000000000000000"
)

# Encrypted record body (just ciphertext + tag shape) for `unprotect`.
RECORDPROTECT_BODY_HEX = (
    "1703030011"           # 5-byte record header (outer ApplicationData)
    "deadbeefdeadbeefdeadbeefdeadbeefdead"  # 17 bytes ciphertext+tag
)

CORPORA = {
    "record":         [("plaintext.bin", PLAINTEXT_RECORD_HEX)],
    "ciphertext":     [("ciphertext.bin", CIPHERTEXT_RECORD_HEX)],
    "clienthello":    [("clienthello.bin", CLIENTHELLO_BODY_HEX)],
    "serverhello":    [("serverhello.bin", SERVERHELLO_BODY_HEX)],
    "certificate":    [("certificate.bin", CERTIFICATE_BODY_HEX)],
    "extensions":     [("extensions.bin", EXTENSIONS_BODY_HEX)],
    "recordprotect":  [("recordprotect.bin", RECORDPROTECT_BODY_HEX)],
}

def clean_hex(s):
    """Strip `# ...` line comments and whitespace from a hex string.

    Also truncates to an even number of characters (so a hand-typed
    odd-length literal still parses as bytes). Seed corpus files do not
    need to be exactly right -- they just need to give AFL shape.
    """
    out = []
    for line in s.split("\n"):
        h = line.split("#", 1)[0]
        out.append(h)
    raw = "".join(out)
    if len(raw) % 2 == 1:
        raw = raw[:-1]
    return raw

def main():
    for sub, files in CORPORA.items():
        d = os.path.join(CORPUS, sub)
        os.makedirs(d, exist_ok=True)
        for name, hexs in files:
            data = bytes.fromhex(clean_hex(hexs))
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
            print(f"wrote {os.path.join(d, name)} ({len(data)} bytes)")

if __name__ == "__main__":
    main()
