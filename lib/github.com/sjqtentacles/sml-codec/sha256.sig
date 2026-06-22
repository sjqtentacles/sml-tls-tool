(* sha256.sig

   SHA-256 (RFC 6234 / FIPS 180-4). Operates on byte strings; returns the
   32-byte digest as raw bytes or as 64 lowercase hex characters. *)

signature SHA256 =
sig
  val digest    : string -> string   (* raw 32-byte digest *)
  val hexDigest : string -> string   (* 64-char lowercase hex *)
end
