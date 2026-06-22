(* x25519.sig
 *
 * Curve25519 Diffie-Hellman key exchange (RFC 7748).
 *
 * All keys and coordinates are little-endian 32-byte strings (one char per byte).
 *)
signature X25519 =
sig
  (* Size in bytes of scalars and u-coordinates (32). *)
  val keySize : int

  (* dh scalar uCoord
   *   Computes the X25519 function: scalar multiplication of the Montgomery
   *   u-coordinate [uCoord] by the (clamped) [scalar].  Both inputs and the
   *   result are little-endian 32-byte strings. *)
  val dh : string -> string -> string

  (* base scalar
   *   Public key for [scalar]: dh scalar basePoint, where the base point has
   *   u = 9. *)
  val base : string -> string

  (* clamp scalar
   *   Apply RFC 7748 section 5 scalar clamping to a 32-byte string. *)
  val clamp : string -> string

  (* toHex bytes
   *   Encode a byte string (e.g. a 32-byte key or u-coordinate) as lowercase
   *   hex. *)
  val toHex : string -> string

  (* fromHex hex
   *   Decode a hex string back to bytes.  NONE on odd length or a non-hex
   *   character.  Round-trip: fromHex (toHex b) = SOME b. *)
  val fromHex : string -> string option
end
