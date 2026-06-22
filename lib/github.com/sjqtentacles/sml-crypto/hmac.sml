(* hmac.sml *)

structure Hmac :> HMAC =
struct
  fun xorByte (pad : int) (c : char) =
    Char.chr (Word.toInt (Word.xorb (Word.fromInt (Char.ord c), Word.fromInt pad)))

  fun xorConst (pad : int) (s : string) = String.map (xorByte pad) s

  (* Generic HMAC (RFC 2104) parameterised by hash and its block size. *)
  fun hmacWith (hash : string -> string) (blockSize : int) key message =
    let
      (* Keys longer than the block are hashed; then zero-padded to block. *)
      val k0 = if String.size key > blockSize then hash key else key
      val k0 = k0 ^ String.implode (List.tabulate (blockSize - String.size k0, fn _ => Char.chr 0))
      val ipad = xorConst 0x36 k0
      val opad = xorConst 0x5c k0
      val inner = hash (ipad ^ message)
    in
      hash (opad ^ inner)
    end

  fun hmacSha1 key message = hmacWith Sha1.digest 64 key message
  fun hmacSha1Hex key message = Base16.encode (hmacSha1 key message)

  fun hmacSha256 key message = hmacWith Sha256.digest 64 key message
  fun hmacSha256Hex key message = Base16.encode (hmacSha256 key message)

  fun hmacSha512 key message = hmacWith Sha512.digest 128 key message
  fun hmacSha512Hex key message = Base16.encode (hmacSha512 key message)

  fun constantEq a b =
    if String.size a <> String.size b then false
    else
      let
        val n = String.size a
        fun loop i acc =
          if i >= n then acc
          else
            loop (i + 1)
              (Word.orb (acc,
                 Word.xorb (Word.fromInt (Char.ord (String.sub (a, i))),
                            Word.fromInt (Char.ord (String.sub (b, i))))))
      in
        Word.toInt (loop 0 0w0) = 0
      end
end
