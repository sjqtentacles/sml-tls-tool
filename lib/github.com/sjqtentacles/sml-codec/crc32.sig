(* crc32.sig

   CRC-32 (ISO 3309 / used by zlib, gzip, PNG). Reflected polynomial
   0xEDB88320, initial value 0xFFFFFFFF, final XOR 0xFFFFFFFF. *)

signature CRC32 =
sig
  (* CRC-32 of a byte string as a 32-bit word. *)
  val crc     : string -> Word32.word
  (* Same, formatted as 8 lowercase hex digits. *)
  val crcHex  : string -> string
end
