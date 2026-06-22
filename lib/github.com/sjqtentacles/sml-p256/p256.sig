(* p256.sig

   NIST P-256 / secp256r1 ECDH + ECDSA verify in pure Standard ML.

   This is the frozen contract for Track A4 (Phase 3b). The Phase 0 stub
   raises `Fail "todo: A4"` from every function; the A4 subagent fills in
   the bodies against NIST CAVP / Wycheproof / FIPS 186-4 vectors.

   Conventions (shared with the sjqtentacles crypto family):
   - All byte payloads (keys, signatures, shared secrets) are RAW BYTE
     STRINGS (one char per byte, 0-255), never hex.
   - Decoders are total: a malformed input returns `NONE` / `false`,
     never a partial value or an uncaught exception. *)

signature P256 =
sig
  (* A point on the P-256 curve in uncompressed SEC1 form (0x04 || X || Y,
     65 bytes) is the canonical wire encoding accepted/produced here.
     The abstract `point` type is for internal use; the public API works
     in the uncompressed byte encoding so callers never need to know the
     representation. *)
  type point

  (* Public key derivation: priv (32-byte scalar) -> uncompressed pub (65 bytes). *)
  val generatePublic : string -> string                 (* priv 32B -> pub *)

  (* ECDH shared-secret derivation. Returns the X-coordinate of the shared
     point (32 bytes), or NONE on a bad peer public key (off-curve /
     identity / malformed). *)
  val ecdh : {privateKey : string, peerPublic : string} -> string option

  (* ECDSA verify over the SHA-256 of `message`. `signatureDer` is the DER
     SEQUENCE { INTEGER r, INTEGER s } encoding. Returns false on a bad
     signature, a bad public key, or a malformed DER encoding (total). *)
  val ecdsaVerify : {publicKey   : string,
                     message     : string,
                     signatureDer: string} -> bool

  (* Curve-membership check on an uncompressed public key (rejects the
     point at infinity, off-curve points, and malformed encodings). *)
  val isOnCurve : string -> bool
end
