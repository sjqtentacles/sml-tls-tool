(* base64.sig

   RFC 4648 Base64 encoding/decoding of byte strings. Standard alphabet
   (`A-Za-z0-9+/`) with `=` padding by default; a URL-safe variant
   (`-` and `_`, no padding) is also provided. Decoding tolerates either
   alphabet and optional padding, and rejects other stray characters. *)

signature BASE64 =
sig
  (* Standard alphabet, with '=' padding. *)
  val encode    : string -> string
  (* URL-safe alphabet ('-' '_'), no padding. *)
  val encodeUrl : string -> string
  (* Decode standard or URL-safe Base64 (padding optional). NONE on a stray
     character or a structurally invalid length. *)
  val decode    : string -> string option
end
