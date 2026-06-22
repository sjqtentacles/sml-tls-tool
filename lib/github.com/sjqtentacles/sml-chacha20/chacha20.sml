(* chacha20.sml
   ChaCha20 stream cipher, Poly1305 MAC, and ChaCha20-Poly1305 AEAD.
   Reference: RFC 8439. *)

(* ------------------------------------------------------------------ *)
(* Shared utilities                                                     *)
(* ------------------------------------------------------------------ *)

local
  fun getLE32 (s : string) (off : int) : Word32.word =
    Word32.orb (Word32.orb (Word32.orb
      (Word32.fromInt (Char.ord (String.sub (s, off))),
       Word32.<< (Word32.fromInt (Char.ord (String.sub (s, off+1))), 0w8)),
       Word32.<< (Word32.fromInt (Char.ord (String.sub (s, off+2))), 0w16)),
       Word32.<< (Word32.fromInt (Char.ord (String.sub (s, off+3))), 0w24))

  fun putLE32 (w : Word32.word) : string =
    let fun b n = Char.chr (Word32.toInt (Word32.andb (Word32.>> (w, Word.fromInt (n*8)), 0wxff)))
    in String.implode [b 0, b 1, b 2, b 3] end

  fun rotl32 (x : Word32.word) (n : Word.word) : Word32.word =
    Word32.orb (Word32.<< (x, n), Word32.>> (x, 0w32 - n))

  fun bytesToHex (s : string) : string =
    let val hex = "0123456789abcdef"
    in String.concat (List.map (fn i =>
         let val b = Char.ord (String.sub (s, i))
         in String.implode [String.sub (hex, b div 16), String.sub (hex, b mod 16)]
         end)
       (List.tabulate (String.size s, fn i => i)))
    end

  fun constantEq (a : string) (b : string) : bool =
    if String.size a <> String.size b then false
    else List.foldl
      (fn ((ca, cb), acc) => acc andalso ca = cb)
      true
      (ListPair.zip (String.explode a, String.explode b))
    (* Note: not truly constant-time in all SML implementations, but
       correct for all inputs. *)
in
  val getLE32    = getLE32
  val putLE32    = putLE32
  val rotl32     = rotl32
  val bytesToHex = bytesToHex
  val constantEq = constantEq
end

(* ------------------------------------------------------------------ *)
(* ChaCha20                                                             *)
(* ------------------------------------------------------------------ *)

structure ChaCha20 : CHACHA20 =
struct
  (* "expa", "nd 3", "2-by", "te k" *)
  val sigma0 = 0wx61707865 : Word32.word
  val sigma1 = 0wx3320646e : Word32.word
  val sigma2 = 0wx79622d32 : Word32.word
  val sigma3 = 0wx6b206574 : Word32.word

  fun qr (sa : Word32.word ref) (sb : Word32.word ref)
         (sc : Word32.word ref) (sd : Word32.word ref) : unit =
    ( sa := Word32.+ (!sa, !sb)
    ; sd := rotl32 (Word32.xorb (!sd, !sa)) 0w16
    ; sc := Word32.+ (!sc, !sd)
    ; sb := rotl32 (Word32.xorb (!sb, !sc)) 0w12
    ; sa := Word32.+ (!sa, !sb)
    ; sd := rotl32 (Word32.xorb (!sd, !sa)) 0w8
    ; sc := Word32.+ (!sc, !sd)
    ; sb := rotl32 (Word32.xorb (!sb, !sc)) 0w7 )

  fun block (key : string) (nonce : string) (counter : Word32.word) : string =
    let
      val init = Array.fromList
        [ sigma0, sigma1, sigma2, sigma3
        , getLE32 key 0,  getLE32 key 4,  getLE32 key 8,  getLE32 key 12
        , getLE32 key 16, getLE32 key 20, getLE32 key 24, getLE32 key 28
        , counter
        , getLE32 nonce 0, getLE32 nonce 4, getLE32 nonce 8 ]
      val st = Array.tabulate (16, fn i => ref (Array.sub (init, i)))
      fun s i = Array.sub (st, i)

      fun doubleRound () =
        ( qr (s 0) (s 4) (s 8)  (s 12)
        ; qr (s 1) (s 5) (s 9)  (s 13)
        ; qr (s 2) (s 6) (s 10) (s 14)
        ; qr (s 3) (s 7) (s 11) (s 15)
        ; qr (s 0) (s 5) (s 10) (s 15)
        ; qr (s 1) (s 6) (s 11) (s 12)
        ; qr (s 2) (s 7) (s 8)  (s 13)
        ; qr (s 3) (s 4) (s 9)  (s 14) )

      val () = List.app (fn _ => doubleRound ()) (List.tabulate (10, fn _ => ()))

      val out = Array.tabulate (16, fn i =>
        Word32.+ (!(s i), Array.sub (init, i)))
    in
      String.concat (List.tabulate (16, fn i => putLE32 (Array.sub (out, i))))
    end

  fun xorStream (key : string) (nonce : string) (msg : string)
                (startCtr : Word32.word) : string =
    let
      val mlen = String.size msg
      val buf  = Array.array (mlen, #"\000")
      val nblk = mlen div 64
      val rem  = mlen mod 64

      val () = List.app (fn b =>
          let val ks = block key nonce (Word32.+ (startCtr, Word32.fromInt b))
          in List.app (fn i =>
               let val off = b*64 + i
               in Array.update (buf, off,
                    Char.chr (Word8.toInt (Word8.xorb
                      (Word8.fromInt (Char.ord (String.sub (msg, off))),
                       Word8.fromInt (Char.ord (String.sub (ks, i)))))))
               end)
             (List.tabulate (64, fn i => i))
          end)
        (List.tabulate (nblk, fn i => i))

      val () = if rem > 0 then
          let val ks  = block key nonce (Word32.+ (startCtr, Word32.fromInt nblk))
              val off0 = nblk * 64
          in List.app (fn i =>
               Array.update (buf, off0 + i,
                 Char.chr (Word8.toInt (Word8.xorb
                   (Word8.fromInt (Char.ord (String.sub (msg, off0 + i))),
                    Word8.fromInt (Char.ord (String.sub (ks, i))))))))
             (List.tabulate (rem, fn i => i))
          end
        else ()
    in
      String.implode (Array.foldr (op ::) [] buf)
    end

  (* Message encryption begins at counter = 1; counter 0 reserved for Poly1305 key *)
  fun encrypt key nonce msg = xorStream key nonce msg 0w1
  fun decrypt key nonce ct  = xorStream key nonce ct  0w1
end

(* ------------------------------------------------------------------ *)
(* Poly1305 one-time MAC (RFC 8439 §2.5)                               *)
(* ------------------------------------------------------------------ *)

structure Poly1305 : POLY1305 =
struct
  val p : IntInf.int =
    IntInf.- (IntInf.<< (IntInf.fromInt 1, 0w130), IntInf.fromInt 5)

  fun loadLE (s : string) (off : int) (len : int) : IntInf.int =
    let
      fun go i acc =
        if i >= len then acc
        else go (i+1)
               (IntInf.orb (acc,
                 IntInf.<< (IntInf.fromInt (Char.ord (String.sub (s, off+i))),
                            Word.fromInt (i*8))))
    in
      IntInf.orb (go 0 (IntInf.fromInt 0),
                  IntInf.<< (IntInf.fromInt 1, Word.fromInt (len*8)))
    end

  fun clamp (r : IntInf.int) : IntInf.int =
    IntInf.andb (r, 0x0ffffffc0ffffffc0ffffffc0fffffff)

  fun fromLE16 (s : string) (off : int) : IntInf.int =
    List.foldl (fn (i, acc) =>
      IntInf.orb (acc,
        IntInf.<< (IntInf.fromInt (Char.ord (String.sub (s, off+i))),
                   Word.fromInt (i*8))))
      (IntInf.fromInt 0) (List.tabulate (16, fn i => i))

  fun mac (key : string) (msg : string) : string =
    let
      val r   = clamp (fromLE16 key 0)
      val s   = fromLE16 key 16
      val mask128 = IntInf.- (IntInf.<< (IntInf.fromInt 1, 0w128), IntInf.fromInt 1)
      val mlen = String.size msg
      val nblk = (mlen + 15) div 16

      val acc = List.foldl (fn (b, acc) =>
          let val chunkLen = Int.min (16, mlen - b*16)
              val n = loadLE msg (b*16) chunkLen
          in IntInf.mod (IntInf.* (IntInf.+ (acc, n), r), p)
          end)
        (IntInf.fromInt 0) (List.tabulate (nblk, fn i => i))

      val tag = IntInf.andb (IntInf.+ (acc, s), mask128)

      fun getByte i =
        IntInf.toInt (IntInf.andb
          (IntInf.div (tag, IntInf.<< (IntInf.fromInt 1, Word.fromInt (i*8))),
           IntInf.fromInt 255))
    in
      String.implode (List.tabulate (16, fn i => Char.chr (getByte i)))
    end

  fun macHex key msg = bytesToHex (mac key msg)
end

(* ------------------------------------------------------------------ *)
(* ChaCha20-Poly1305 AEAD (RFC 8439 §2.8)                              *)
(* ------------------------------------------------------------------ *)

structure ChaCha20Poly1305 : CHACHA20_POLY1305 =
struct
  fun pad16 n =
    String.implode (List.tabulate ((16 - n mod 16) mod 16, fn _ => #"\000"))

  fun le64 (n : int) : string =
    let val inf = IntInf.fromInt n
    in String.implode (List.tabulate (8, fn i =>
         Char.chr (IntInf.toInt (IntInf.andb
           (IntInf.div (inf, IntInf.<< (IntInf.fromInt 1, Word.fromInt (i*8))),
            IntInf.fromInt 255)))))
    end

  fun polyKey (key : string) (nonce : string) : string =
    String.substring (ChaCha20.block key nonce 0w0, 0, 32)

  fun authMsg (aad : string) (ct : string) : string =
    aad ^ pad16 (String.size aad) ^
    ct  ^ pad16 (String.size ct)  ^
    le64 (String.size aad) ^ le64 (String.size ct)

  fun seal (key : string) (nonce : string) (aad : string) (msg : string) : string =
    let
      val ct  = ChaCha20.encrypt key nonce msg
      val tag = Poly1305.mac (polyKey key nonce) (authMsg aad ct)
    in
      ct ^ tag
    end

  fun open' (key : string) (nonce : string) (aad : string) (sealed : string)
      : string option =
    let val slen = String.size sealed
    in if slen < 16 then NONE
       else
         let
           val ct       = String.substring (sealed, 0, slen - 16)
           val tag      = String.substring (sealed, slen - 16, 16)
           val expected = Poly1305.mac (polyKey key nonce) (authMsg aad ct)
         in
           if constantEq expected tag
           then SOME (ChaCha20.decrypt key nonce ct)
           else NONE
         end
    end
end

(* ------------------------------------------------------------------ *)
(* XChaCha20-Poly1305 (24-byte nonce)                                  *)
(* ------------------------------------------------------------------ *)

structure XChaCha20Poly1305 =
struct
  (* HChaCha20: apply 20 rounds but return words 0-3 and 12-15
     (no addition with initial state) as a 32-byte subkey. *)
  fun hchacha20 (key : string) (nonce16 : string) : string =
    let
      val init = Array.fromList
        [ 0wx61707865, 0wx3320646e, 0wx79622d32, 0wx6b206574
        , getLE32 key 0,  getLE32 key 4,  getLE32 key 8,  getLE32 key 12
        , getLE32 key 16, getLE32 key 20, getLE32 key 24, getLE32 key 28
        , getLE32 nonce16 0, getLE32 nonce16 4
        , getLE32 nonce16 8, getLE32 nonce16 12 ] : Word32.word array
      val st = Array.tabulate (16, fn i => ref (Array.sub (init, i)))
      fun s i = Array.sub (st, i)

      fun qr sa sb sc sd =
        ( sa := Word32.+ (!sa, !sb)
        ; sd := rotl32 (Word32.xorb (!sd, !sa)) 0w16
        ; sc := Word32.+ (!sc, !sd)
        ; sb := rotl32 (Word32.xorb (!sb, !sc)) 0w12
        ; sa := Word32.+ (!sa, !sb)
        ; sd := rotl32 (Word32.xorb (!sd, !sa)) 0w8
        ; sc := Word32.+ (!sc, !sd)
        ; sb := rotl32 (Word32.xorb (!sb, !sc)) 0w7 )

      fun doubleRound () =
        ( qr (s 0) (s 4) (s 8)  (s 12)
        ; qr (s 1) (s 5) (s 9)  (s 13)
        ; qr (s 2) (s 6) (s 10) (s 14)
        ; qr (s 3) (s 7) (s 11) (s 15)
        ; qr (s 0) (s 5) (s 10) (s 15)
        ; qr (s 1) (s 6) (s 11) (s 12)
        ; qr (s 2) (s 7) (s 8)  (s 13)
        ; qr (s 3) (s 4) (s 9)  (s 14) )

      val () = List.app (fn _ => doubleRound ()) (List.tabulate (10, fn _ => ()))
    in
      String.concat
        [ putLE32 (!(s 0)),  putLE32 (!(s 1))
        , putLE32 (!(s 2)),  putLE32 (!(s 3))
        , putLE32 (!(s 12)), putLE32 (!(s 13))
        , putLE32 (!(s 14)), putLE32 (!(s 15)) ]
    end

  fun sub (key : string) (nonce24 : string) : string * string =
    let
      val subkey = hchacha20 key (String.substring (nonce24, 0, 16))
      val n12    = "\000\000\000\000" ^ String.substring (nonce24, 16, 8)
    in
      (subkey, n12)
    end

  fun seal (key : string) (nonce : string) (aad : string) (msg : string) : string =
    let val (k2, n2) = sub key nonce
    in ChaCha20Poly1305.seal k2 n2 aad msg end

  fun open' (key : string) (nonce : string) (aad : string) (sealed : string) : string option =
    let val (k2, n2) = sub key nonce
    in ChaCha20Poly1305.open' k2 n2 aad sealed end
end
