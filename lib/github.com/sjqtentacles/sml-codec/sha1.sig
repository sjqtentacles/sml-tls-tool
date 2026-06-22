(* sha1.sig

   SHA-1 (RFC 3174 / FIPS 180-1). Operates on byte strings; returns the
   20-byte digest as raw bytes or as 40 lowercase hex characters. *)

signature SHA1 =
sig
  (* Raw 20-byte digest. *)
  val digest    : string -> string
  (* 40-character lowercase hex digest. *)
  val hexDigest : string -> string
end
