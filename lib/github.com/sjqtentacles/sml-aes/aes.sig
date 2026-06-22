(* aes.sig — AES block cipher (FIPS 197) + modes of operation. *)

signature AES_BLOCK =
sig
  type key
  val keySize   : key -> int
  val expand128 : string -> key
  val expand192 : string -> key
  val expand256 : string -> key
  val encrypt   : key -> string -> string
  val decrypt   : key -> string -> string
end

signature AES_MODE =
sig
  val encrypt : string -> string -> string -> string
  val decrypt : string -> string -> string -> string
end

signature AES_GCM =
sig
  val seal  : string -> string -> string -> string -> string
  val open' : string -> string -> string -> string -> string option
end
