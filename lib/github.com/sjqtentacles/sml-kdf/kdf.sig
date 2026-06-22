(* kdf.sig

   Key-derivation functions that complement the PBKDF2 already provided by
   sml-crypto (Pbkdf2.pbkdf2Sha256/512):

     - HKDF  (RFC 5869) -- extract-then-expand over HMAC-SHA-256 / HMAC-SHA-512
     - scrypt (RFC 7914) -- the memory-hard KDF (Salsa20/8 core + PBKDF2 wrapper)

   All inputs and outputs are raw byte strings (one char per byte, 0-255),
   matching the rest of the sjqtentacles crypto/codec family. Everything here
   is pure and deterministic: identical inputs give byte-identical outputs on
   both MLton and Poly/ML.

   Argon2id (RFC 9106) is a planned phase-2 milestone: it requires a BLAKE2b
   primitive that does not yet exist in the ecosystem, so it is intentionally
   out of scope for this release (see the README). *)

signature KDF =
sig
  (* The HMAC pseudo-random function used by HKDF. *)
  datatype prf = HmacSha256 | HmacSha512

  exception Kdf of string

  structure Hkdf :
  sig
    (* extract prf {salt, ikm} -> PRK
       HKDF-Extract: PRK = HMAC(salt, ikm). A zero-length salt is replaced by
       HashLen zero bytes, per RFC 5869. *)
    val extract : prf -> {salt:string, ikm:string} -> string

    (* expand prf {prk, info, len} -> OKM of `len` bytes
       HKDF-Expand. Raises Kdf if len > 255*HashLen. *)
    val expand  : prf -> {prk:string, info:string, len:int} -> string

    (* derive prf {salt, ikm, info, len} -> OKM = expand (extract ...) *)
    val derive  : prf -> {salt:string, ikm:string, info:string, len:int}
                      -> string
  end

  (* scrypt {password, salt, n, r, p, dkLen} -> derived key of dkLen bytes.
     `n` is the CPU/memory cost (a power of two > 1), `r` the block size factor,
     `p` the parallelisation factor. Raises Kdf on invalid parameters. *)
  val scrypt : {password:string, salt:string, n:int, r:int, p:int, dkLen:int}
            -> string
end
