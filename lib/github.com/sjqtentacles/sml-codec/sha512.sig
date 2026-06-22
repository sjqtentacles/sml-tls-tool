(* sha512.sig

   SHA-512 (RFC 6234 / FIPS 180-4). Operates on byte strings; returns the
   64-byte digest as raw bytes or as 128 lowercase hex characters. *)

signature SHA512 =
sig
  val digest    : string -> string   (* raw 64-byte digest *)
  val hexDigest : string -> string   (* 128-char lowercase hex *)
end
