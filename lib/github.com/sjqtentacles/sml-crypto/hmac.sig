(* hmac.sig

   HMAC (RFC 2104) over SHA-1, SHA-256 and SHA-512. Operates on byte strings;
   returns the raw MAC or its lowercase hex form. *)

signature HMAC =
sig
  (* hmacSha1 key message -> raw 20-byte MAC *)
  val hmacSha1      : string -> string -> string
  val hmacSha1Hex   : string -> string -> string

  (* hmacSha256 key message -> raw 32-byte MAC *)
  val hmacSha256    : string -> string -> string
  val hmacSha256Hex : string -> string -> string

  (* hmacSha512 key message -> raw 64-byte MAC *)
  val hmacSha512    : string -> string -> string
  val hmacSha512Hex : string -> string -> string

  (* Constant-time equality of two equal-length byte strings. Returns false
     for differing lengths. Comparison time depends only on the common
     length, not on where the first difference is. *)
  val constantEq : string -> string -> bool
end
