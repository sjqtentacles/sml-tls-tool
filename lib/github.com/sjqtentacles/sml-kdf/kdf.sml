(* kdf.sml

   HKDF (RFC 5869) over HMAC-SHA-256/512 from sml-crypto, plus scrypt
   (RFC 7914) with an internally-implemented Salsa20/8 core and the
   PBKDF2-HMAC-SHA256 wrapper from sml-crypto.

   scrypt's mixing core is Salsa20/8 -- NOT SHA and NOT ChaCha20 -- so it is
   implemented here directly; SHA-256 only appears inside the outer/inner
   PBKDF2 (Pbkdf2.pbkdf2Sha256). *)

structure Kdf :> KDF =
struct
  datatype prf = HmacSha256 | HmacSha512

  exception Kdf of string

  (* ------------------------------------------------------------------ *)
  (* HKDF (RFC 5869)                                                      *)
  (* ------------------------------------------------------------------ *)

  fun hashLen HmacSha256 = 32
    | hashLen HmacSha512 = 64

  fun hmac HmacSha256 = Hmac.hmacSha256
    | hmac HmacSha512 = Hmac.hmacSha512

  structure Hkdf =
  struct
    fun extract prf {salt, ikm} =
      let val salt' = if String.size salt = 0
                      then String.implode (List.tabulate (hashLen prf, fn _ => #"\000"))
                      else salt
      in hmac prf salt' ikm end

    fun expand prf {prk, info, len} =
      let
        val hl = hashLen prf
        val n  = (len + hl - 1) div hl
        val () = if len < 0 then raise Kdf "expand: negative length" else ()
        val () = if n > 255 then raise Kdf "expand: length exceeds 255*HashLen" else ()
        fun loop (i, prev, acc) =
          if i > n then String.concat (List.rev acc)
          else
            let val t = hmac prf prk (prev ^ info ^ String.str (Char.chr i))
            in loop (i + 1, t, t :: acc) end
        val okm = loop (1, "", [])
      in String.substring (okm, 0, len) end

    fun derive prf {salt, ikm, info, len} =
      expand prf {prk = extract prf {salt = salt, ikm = ikm}, info = info, len = len}
  end

  (* ------------------------------------------------------------------ *)
  (* scrypt (RFC 7914)                                                    *)
  (* ------------------------------------------------------------------ *)

  (* Little-endian 32-bit load/store between byte strings and Word32 arrays. *)
  fun bytesToWords (s : string) : Word32.word array =
    let
      val n = String.size s div 4
      fun w i =
        let fun b k = Word32.fromInt (Char.ord (String.sub (s, i*4 + k)))
        in Word32.orb (b 0,
             Word32.orb (Word32.<< (b 1, 0w8),
               Word32.orb (Word32.<< (b 2, 0w16), Word32.<< (b 3, 0w24)))) end
    in Array.tabulate (n, w) end

  fun wordsToBytes (a : Word32.word array) : string =
    let
      fun byteOf w shift =
        Char.chr (Word32.toInt (Word32.andb (Word32.>> (w, shift), 0wxff)))
      val n = Array.length a
    in
      String.concat (List.tabulate (n, fn i =>
        let val w = Array.sub (a, i)
        in String.implode [byteOf w 0w0, byteOf w 0w8, byteOf w 0w16, byteOf w 0w24] end))
    end

  fun rotl (x, n) = Word32.orb (Word32.<< (x, n), Word32.>> (x, 0w32 - n))

  (* Salsa20/8 core on a 16-word block: out = in + 8 rounds(in). *)
  fun salsa20_8 (input : Word32.word array) : Word32.word array =
    let
      val x = Array.tabulate (16, fn i => Array.sub (input, i))
      fun get i = Array.sub (x, i)
      fun set (i, v) = Array.update (x, i, v)
      fun qr (a, b, c, d) =
        ( set (b, Word32.xorb (get b, rotl (Word32.+ (get a, get d), 0w7)))
        ; set (c, Word32.xorb (get c, rotl (Word32.+ (get b, get a), 0w9)))
        ; set (d, Word32.xorb (get d, rotl (Word32.+ (get c, get b), 0w13)))
        ; set (a, Word32.xorb (get a, rotl (Word32.+ (get d, get c), 0w18))) )
      fun doubleRound () =
        ( qr (0, 4, 8, 12);  qr (5, 9, 13, 1);  qr (10, 14, 2, 6);  qr (15, 3, 7, 11)
        ; qr (0, 1, 2, 3);   qr (5, 6, 7, 4);   qr (10, 11, 8, 9);  qr (15, 12, 13, 14) )
      val () = List.app (fn _ => doubleRound ()) [(), (), (), ()]  (* 4 double rounds = 8 rounds *)
    in
      Array.tabulate (16, fn i => Word32.+ (get i, Array.sub (input, i)))
    end

  (* BlockMix on B (2r 64-byte blocks = 32r words), output 32r words. *)
  fun blockMix (r : int) (b : Word32.word array) : Word32.word array =
    let
      val twoR = 2 * r
      fun block i = Array.tabulate (16, fn k => Array.sub (b, i*16 + k))
      fun xorBlock (p, q) = Array.tabulate (16, fn k =>
        Word32.xorb (Array.sub (p, k), Array.sub (q, k)))
      val out = Array.array (32 * r, 0w0 : Word32.word)
      val xref = ref (block (twoR - 1))
      fun place (destBlock, src) =
        List.app (fn k => Array.update (out, destBlock*16 + k, Array.sub (src, k)))
                 (List.tabulate (16, fn k => k))
      val () =
        List.app (fn i =>
          let val x' = salsa20_8 (xorBlock (!xref, block i))
              val () = xref := x'
              (* even i -> first half (i div 2); odd i -> second half (r + i div 2) *)
              val dest = if i mod 2 = 0 then i div 2 else r + (i div 2)
          in place (dest, x') end)
          (List.tabulate (twoR, fn i => i))
    in out end

  (* ROMix (SMix) on B (32r words), cost N. *)
  fun roMix (r : int) (n : int) (b : Word32.word array) : Word32.word array =
    let
      val words = 32 * r
      fun copy a = Array.tabulate (words, fn i => Array.sub (a, i))
      val v = Array.tabulate (n, fn _ => Array.array (words, 0w0 : Word32.word))
      val x = ref (copy b)
      val () =
        List.app (fn i =>
          ( Array.update (v, i, copy (!x))
          ; x := blockMix r (!x) )) (List.tabulate (n, fn i => i))
      (* Integerify mod n. n is a power of two, so j = X mod n is just the low
         log2(n) bits of the integer formed by the last 64-byte block; masking
         with (n-1) in Word32 avoids converting a full 32-bit value to Int
         (which would overflow a 32-bit Int target). *)
      val mask = Word32.fromInt (n - 1)
      fun jOf a = Word32.toInt (Word32.andb (Array.sub (a, words - 16), mask))
      fun xorInto (dst, src) =
        List.app (fn k => Array.update (dst, k,
          Word32.xorb (Array.sub (dst, k), Array.sub (src, k))))
          (List.tabulate (words, fn k => k))
      val () =
        List.app (fn _ =>
          let
            val j = jOf (!x)
            val xc = copy (!x)
            val () = xorInto (xc, Array.sub (v, j))
          in x := blockMix r xc end) (List.tabulate (n, fn i => i))
    in !x end

  fun isPowerOfTwo n = n > 1 andalso Word.andb (Word.fromInt n, Word.fromInt (n - 1)) = 0w0

  fun scrypt {password, salt, n, r, p, dkLen} =
    let
      val () = if not (isPowerOfTwo n) then raise Kdf "scrypt: n must be a power of two > 1" else ()
      val () = if r < 1 orelse p < 1 then raise Kdf "scrypt: r and p must be >= 1" else ()
      val () = if dkLen < 1 then raise Kdf "scrypt: dkLen must be >= 1" else ()
      val blockBytes = 128 * r
      (* B = PBKDF2-HMAC-SHA256(password, salt, 1, p*128*r) *)
      val b0 = Pbkdf2.pbkdf2Sha256
                 {password = password, salt = salt, iters = 1, dkLen = p * blockBytes}
      (* Mix each of the p blocks through ROMix. *)
      val mixed =
        String.concat (List.tabulate (p, fn i =>
          let val chunk = String.substring (b0, i * blockBytes, blockBytes)
              val mixedWords = roMix r n (bytesToWords chunk)
          in wordsToBytes mixedWords end))
      (* DK = PBKDF2-HMAC-SHA256(password, mixed, 1, dkLen) *)
    in
      Pbkdf2.pbkdf2Sha256 {password = password, salt = mixed, iters = 1, dkLen = dkLen}
    end
end
