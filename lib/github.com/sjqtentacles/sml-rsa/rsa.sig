(* rsa.sig

   RSA in pure Standard ML: key generation, the three PKCS#1 padding schemes
   (RSASSA-PKCS1-v1_5 signatures, RSAES-PKCS1-v1_5 encryption, RSAES-OAEP
   encryption, RSASSA-PSS signatures) and DER/PEM key import/export, all
   anchored on RFC 8017 (PKCS#1 v2.2).

   Byte convention.  Every cryptographic value -- messages, signatures,
   ciphertexts, seeds, salts, DER blobs -- is a raw [string]: one byte per
   [char], codepoints 0..255.  Arbitrary-precision integers (moduli, exponents,
   primes) are carried by the vendored [BigInt] (sml-bigint), so 2048-bit and
   larger keys round-trip exactly.  `*Hex` helpers convert between raw bytes and
   lowercase hexadecimal for readable vectors and interop.

   Determinism.  Nothing here reads the clock, the OS RNG, or any global state.
   Every operation that needs randomness takes it as an explicit argument: key
   generation takes [randomBytes], PKCS#1 v1.5 encryption takes [randomBytes],
   OAEP takes a [seed], and PSS takes a [salt].  Supplying fixed bytes makes the
   whole library reproducible and byte-identical under MLton and Poly/ML, which
   is what lets the official RFC 8017 / PKCS#1 test vectors be checked exactly.

   Signature verification ([verify] / [verifyPss]) is the entry point a higher
   level library such as sml-x509 uses to check a certificate signature: feed it
   the issuer's [pubkey], the hash named in the certificate, the to-be-signed
   bytes as [msg], and the signature value as [sgn]. *)

signature RSA =
sig
  (* ---- keys ----

     An RSA public key is the modulus [n] and public exponent [e].  A private
     key additionally carries the private exponent [d], the prime factors
     [p],[q] and the three CRT speed-up parameters
       dp = d mod (p-1),  dq = d mod (q-1),  qinv = q^-1 mod p
     so that private operations use the (about 4x faster) CRT path. *)
  type pubkey  = { n : BigInt.int, e : BigInt.int }
  type privkey = { n : BigInt.int, e : BigInt.int, d : BigInt.int
                 , p : BigInt.int, q : BigInt.int
                 , dp : BigInt.int, dq : BigInt.int, qinv : BigInt.int }
  type keypair = { pub : pubkey, priv : privkey }

  (* Raised on malformed keys, padding/decoding failures, messages that do not
     fit the modulus, bad DER, and the like. *)
  exception RSA of string

  (* Hash functions backing the padding schemes (provided by sml-codec). *)
  datatype hash = SHA1 | SHA256 | SHA512

  (* ---- key generation ----

     [generate {bits, e, randomBytes}] produces a fresh keypair whose modulus is
     exactly [bits] bits ([bits] even, >= 512).  Two probable primes are found
     by drawing [bits div 2] random bytes from [randomBytes] (a function from a
     requested byte count to that many raw bytes), forcing the top two and the
     low bit, then stepping by 2 through BigInt Miller-Rabin candidates -- so a
     single deterministic [randomBytes] makes the whole search reproducible.
     [e] must be odd, > 1, and coprime to (p-1)(q-1) (65537 is the usual
     choice). *)
  val generate : { bits : int, e : BigInt.int, randomBytes : int -> string }
                 -> keypair

  (* Byte length k of the modulus (ceil of its bit length over 8). *)
  val modulusBytes : pubkey -> int
  (* The public half of a private key. *)
  val pubOf : privkey -> pubkey

  (* ---- RSASSA-PKCS1-v1_5 signatures (RFC 8017 sec. 8.2) ----

     Deterministic: a DigestInfo wrapping H(msg) is padded as
     0x00 01 FF..FF 00 || DigestInfo and raised to [d].  [verify] returns true
     iff [sgn] is a valid signature of [msg] under [pub] for the named [hash]. *)
  val sign   : { priv : privkey, hash : hash, msg : string } -> string
  val verify : { pub : pubkey, hash : hash, msg : string, sgn : string } -> bool

  (* ---- RSAES-PKCS1-v1_5 encryption (RFC 8017 sec. 7.2) ----

     [encrypt] pads as 0x00 02 PS 00 || msg with [PS] nonzero padding drawn from
     [randomBytes]; [msg] must be at most k-11 bytes.  [decrypt] removes the
     padding (raising [RSA] on a malformed block). *)
  val encrypt : { pub : pubkey, msg : string, randomBytes : int -> string }
                -> string
  val decrypt : { priv : privkey, ct : string } -> string

  (* ---- RSAES-OAEP encryption (RFC 8017 sec. 7.1) ----

     MGF1 is built from the chosen [hash]; [label] is the optional associated
     label (usually "").  [seed] must be exactly hLen bytes (the hash output
     length); supplying the official vector seed reproduces the vector
     ciphertext exactly.  [msg] must be at most k - 2*hLen - 2 bytes. *)
  val encryptOaep : { pub : pubkey, hash : hash, label : string
                    , seed : string, msg : string } -> string
  val decryptOaep : { priv : privkey, hash : hash, label : string
                    , ct : string } -> string

  (* ---- RSASSA-PSS signatures (RFC 8017 sec. 8.1) ----

     MGF1 is built from the chosen [hash].  [salt] is the explicit salt (its
     length is the salt length; "" means a zero-length salt); supplying the
     official vector salt reproduces the vector signature exactly.  [verifyPss]
     is told the expected [saltLen] in bytes. *)
  val signPss   : { priv : privkey, hash : hash, salt : string, msg : string }
                  -> string
  val verifyPss : { pub : pubkey, hash : hash, saltLen : int
                  , msg : string, sgn : string } -> bool

  (* ---- DER / PEM key import & export ----

     PKCS#1 (RFC 8017 App. A.1):
       RSAPublicKey  ::= SEQUENCE { modulus, publicExponent }
       RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, dP, dQ, qInv }
     SubjectPublicKeyInfo (X.509) and PKCS#8 PrivateKeyInfo wrap those in the
     standard rsaEncryption (1.2.840.113549.1.1.1) AlgorithmIdentifier. *)
  val encodePublicDer  : pubkey  -> string   (* PKCS#1 RSAPublicKey  *)
  val decodePublicDer  : string  -> pubkey
  val encodePrivateDer : privkey -> string   (* PKCS#1 RSAPrivateKey *)
  val decodePrivateDer : string  -> privkey

  val encodeSpkiDer  : pubkey  -> string     (* SubjectPublicKeyInfo *)
  val decodeSpkiDer  : string  -> pubkey
  val encodePkcs8Der : privkey -> string     (* PKCS#8 PrivateKeyInfo *)
  val decodePkcs8Der : string  -> privkey

  (* PEM wrappers.  Export uses the SPKI / PKCS#8 forms with the generic
     "PUBLIC KEY" / "PRIVATE KEY" labels; import accepts either the generic
     wrapping or the bare PKCS#1 "RSA PUBLIC KEY" / "RSA PRIVATE KEY" forms. *)
  val encodePublicPem  : pubkey  -> string
  val decodePublicPem  : string  -> pubkey
  val encodePrivatePem : privkey -> string
  val decodePrivatePem : string  -> privkey

  (* ---- hex helpers ---- *)
  (* Raw bytes <-> lowercase hex.  [fromHex] ignores ASCII whitespace and
     raises [RSA] on an odd length or a non-hex digit. *)
  val toHex   : string -> string
  val fromHex : string -> string
end
