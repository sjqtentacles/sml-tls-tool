(* aead.sig

   A single algorithm-agnostic AEAD (authenticated encryption with associated
   data) facade over the primitives that already exist in the ecosystem:

     - ChaCha20-Poly1305 (RFC 8439)          -- from sml-chacha20
     - AES-128-GCM / AES-256-GCM (NIST GCM)  -- from sml-aes

   Callers program against one `alg`-keyed `seal`/`open'` interface instead of
   three separate structures, which is what downstream protocol work
   (sml-tls / sml-ssh) wants. The standalone Poly1305 one-time MAC is also
   re-exported.

   Conventions (shared with the rest of the sjqtentacles crypto family):
   - All keys / nonces / aad / plaintext / ciphertext are RAW BYTE STRINGS
     (one char per byte, 0-255), never hex.
   - `seal` returns ciphertext WITH the 16-byte authentication tag APPENDED
     (ciphertext||tag), exactly as the underlying RFC/NIST constructions do.
   - `open'` takes that same ciphertext||tag, verifies the tag in constant
     time, and returns `SOME plaintext` on success or `NONE` if authentication
     fails (tampered ciphertext/tag/aad/nonce) or the input is too short. *)

signature AEAD =
sig
  datatype alg = ChaCha20Poly1305   (* 256-bit key, 96-bit nonce  *)
               | AesGcm128          (* 128-bit key, 96-bit nonce  *)
               | AesGcm256          (* 256-bit key, 96-bit nonce  *)

  (* Raised by `seal`/`open'` when the key or nonce length is wrong for the
     chosen algorithm (a programming error, distinct from an auth failure). *)
  exception Aead of string

  (* The authentication tag length, in bytes, for every algorithm here. = 16 *)
  val tagLen   : int

  (* Required key / nonce length in bytes for an algorithm. *)
  val keyLen   : alg -> int
  val nonceLen : alg -> int

  (* seal alg {key, nonce, aad, plaintext} -> ciphertext || tag

     Encrypts and authenticates `plaintext` (and authenticates `aad`).
     Raises `Aead` if `key`/`nonce` lengths do not match the algorithm. *)
  val seal  : alg -> {key:string, nonce:string, aad:string, plaintext:string}
                  -> string

  (* open' alg {key, nonce, aad, ciphertext} -> SOME plaintext | NONE

     `ciphertext` is the ciphertext||tag produced by `seal`. Returns
     `SOME plaintext` iff the tag verifies, otherwise `NONE`. Raises `Aead`
     if `key`/`nonce` lengths do not match the algorithm. *)
  val open' : alg -> {key:string, nonce:string, aad:string, ciphertext:string}
                  -> string option

  (* The standalone Poly1305 one-time authenticator (RFC 8439 section 2.5):
     `mac key msg` with a 32-byte one-time `key` -> 16-byte tag. *)
  structure Poly1305 :
  sig
    val mac    : string -> string -> string   (* raw 16-byte tag    *)
    val macHex : string -> string -> string   (* 32-char hex tag    *)
  end
end
