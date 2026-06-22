(* base16.sig

   Lowercase/uppercase hexadecimal (RFC 4648 Base16) encoding and decoding
   of byte strings. Decoding is case-insensitive and rejects odd-length or
   non-hex input. *)

signature BASE16 =
sig
  (* Encode each byte as two lowercase hex digits. *)
  val encode  : string -> string
  (* Encode using uppercase hex digits. *)
  val encodeUpper : string -> string
  (* Decode hex text to bytes. NONE on odd length or a non-hex character. *)
  val decode  : string -> string option
end
