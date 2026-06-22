(* sha1.sml

   Straightforward SHA-1 over a byte string. All arithmetic is on
   Word32.word, which is exactly 32 bits, so the usual wrap-around is
   automatic. Message length is tracked as an IntInf to support inputs
   beyond 2^29 bytes. *)

structure Sha1 :> SHA1 =
struct
  type w = Word32.word
  val andb = Word32.andb
  val orb  = Word32.orb
  val xorb = Word32.xorb
  infix andb orb xorb
  fun << (a, b) = Word32.<< (a, b)
  fun >> (a, b) = Word32.>> (a, b)
  infix << >>

  fun notb w = Word32.xorb (w, 0wxFFFFFFFF)

  fun rotl (w, n : int) =
    (w << Word.fromInt n) orb (w >> Word.fromInt (32 - n))

  (* Pad the message per the spec and return a list of 32-bit big-endian
     words (each block is 16 words). *)
  fun padded (msg : string) : Word32.word list =
    let
      val len = String.size msg
      val bitLen = IntInf.fromInt len * 8
      (* append 0x80, then zeros until length === 56 (mod 64), then 8-byte
         big-endian bit length. *)
      val withOne = msg ^ String.str (Char.chr 0x80)
      val padZeros : int =
        let val m = String.size withOne mod 64
        in if m <= 56 then 56 - m else 120 - m end
      val zeros = String.implode (List.tabulate (padZeros, fn _ => Char.chr 0))
      fun lenByte (i : int) =
        Char.chr (IntInf.toInt (IntInf.andb (IntInf.~>> (bitLen, Word.fromInt (i * 8)), 0xFF)))
      val lenBytes = String.implode (List.map lenByte [7,6,5,4,3,2,1,0])
      val full = withOne ^ zeros ^ lenBytes
      val n = String.size full
      fun word (i : int) =
        let
          fun b (k : int) = Word32.fromInt (Char.ord (String.sub (full, i + k)))
        in
          (b 0 << 0w24) orb (b 1 << 0w16) orb (b 2 << 0w8) orb (b 3)
        end
      fun loop (i : int) acc =
        if i >= n then List.rev acc else loop (i + 4) (word i :: acc)
    in
      loop 0 []
    end

  fun chunk16 ws =
    case ws of
        [] => []
      | _ =>
          let
            fun take 0 xs acc = (List.rev acc, xs)
              | take (k : int) (x :: xs) acc = take (k - 1) xs (x :: acc)
              | take _ [] acc = (List.rev acc, [])
            val (blk, rest) = take 16 ws []
          in
            blk :: chunk16 rest
          end

  fun processBlock ((h0,h1,h2,h3,h4), block) =
    let
      val w = Array.array (80, 0w0 : Word32.word)
      val _ = List.foldl (fn (x, i) => (Array.update (w, i, x); i + 1)) 0 block
      fun extend (i : int) =
        if i >= 80 then ()
        else
          (Array.update (w, i,
             rotl (Array.sub (w, i-3) xorb Array.sub (w, i-8)
                   xorb Array.sub (w, i-14) xorb Array.sub (w, i-16), 1));
           extend (i + 1))
      val () = extend 16

      fun round (i : int, a, b, c, d, e) =
        if i >= 80 then (a, b, c, d, e)
        else
          let
            val (f, k) =
              if i < 20 then ((b andb c) orb ((notb b) andb d), 0wx5A827999)
              else if i < 40 then (b xorb c xorb d, 0wx6ED9EBA1)
              else if i < 60 then ((b andb c) orb (b andb d) orb (c andb d), 0wx8F1BBCDC)
              else (b xorb c xorb d, 0wxCA62C1D6)
            val tmp = Word32.+ (Word32.+ (Word32.+ (Word32.+ (rotl (a, 5), f), e), k), Array.sub (w, i))
          in
            round (i + 1, tmp, a, rotl (b, 30), c, d)
          end
      val (a, b, c, d, e) = round (0, h0, h1, h2, h3, h4)
    in
      (Word32.+ (h0, a), Word32.+ (h1, b), Word32.+ (h2, c), Word32.+ (h3, d), Word32.+ (h4, e))
    end

  fun digestWords msg =
    let
      val blocks = chunk16 (padded msg)
      val init = (0wx67452301, 0wxEFCDAB89, 0wx98BADCFE, 0wx10325476, 0wxC3D2E1F0)
    in
      List.foldl (fn (blk, st) => processBlock (st, blk)) init blocks
    end

  fun wordBytes w =
    String.implode
      (List.map
        (fn (sh : int) => Char.chr (Word32.toInt ((w >> Word.fromInt sh) andb 0wxFF)))
        [24, 16, 8, 0])

  fun digest msg =
    let val (h0,h1,h2,h3,h4) = digestWords msg
    in String.concat (List.map wordBytes [h0,h1,h2,h3,h4]) end

  fun hexDigest msg =
    let val (h0,h1,h2,h3,h4) = digestWords msg
        fun hex w = StringCvt.padLeft #"0" 8 (Word32.fmt StringCvt.HEX w)
    in String.map Char.toLower (String.concat (List.map hex [h0,h1,h2,h3,h4])) end
end
