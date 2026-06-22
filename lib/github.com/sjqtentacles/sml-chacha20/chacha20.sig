(* chacha20.sig
   ChaCha20-Poly1305 authenticated encryption (RFC 8439). *)

signature CHACHA20 =
sig
  val block   : string -> string -> Word32.word -> string
  val encrypt : string -> string -> string -> string
  val decrypt : string -> string -> string -> string
end

signature POLY1305 =
sig
  val mac    : string -> string -> string
  val macHex : string -> string -> string
end

signature CHACHA20_POLY1305 =
sig
  val seal  : string -> string -> string -> string -> string
  val open' : string -> string -> string -> string -> string option
end
