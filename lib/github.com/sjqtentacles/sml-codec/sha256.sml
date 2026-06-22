(* sha256.sml

   SHA-256 over a byte string, all arithmetic on Word32.word. Padding and
   block splitting mirror sha1.sml. *)

structure Sha256 :> SHA256 =
struct
  val andb = Word32.andb
  val orb  = Word32.orb
  val xorb = Word32.xorb
  infix andb orb xorb
  fun << (a, b) = Word32.<< (a, b)
  fun >> (a, b) = Word32.>> (a, b)
  infix << >>
  val op ++ = Word32.+
  infix 6 ++

  fun notb w = Word32.xorb (w, 0wxFFFFFFFF)

  fun rotr (w, n : int) =
    (w >> Word.fromInt n) orb (w << Word.fromInt (32 - n))

  val k : Word32.word vector = Vector.fromList
    [0wx428a2f98,0wx71374491,0wxb5c0fbcf,0wxe9b5dba5,0wx3956c25b,0wx59f111f1,
     0wx923f82a4,0wxab1c5ed5,0wxd807aa98,0wx12835b01,0wx243185be,0wx550c7dc3,
     0wx72be5d74,0wx80deb1fe,0wx9bdc06a7,0wxc19bf174,0wxe49b69c1,0wxefbe4786,
     0wx0fc19dc6,0wx240ca1cc,0wx2de92c6f,0wx4a7484aa,0wx5cb0a9dc,0wx76f988da,
     0wx983e5152,0wxa831c66d,0wxb00327c8,0wxbf597fc7,0wxc6e00bf3,0wxd5a79147,
     0wx06ca6351,0wx14292967,0wx27b70a85,0wx2e1b2138,0wx4d2c6dfc,0wx53380d13,
     0wx650a7354,0wx766a0abb,0wx81c2c92e,0wx92722c85,0wxa2bfe8a1,0wxa81a664b,
     0wxc24b8b70,0wxc76c51a3,0wxd192e819,0wxd6990624,0wxf40e3585,0wx106aa070,
     0wx19a4c116,0wx1e376c08,0wx2748774c,0wx34b0bcb5,0wx391c0cb3,0wx4ed8aa4a,
     0wx5b9cca4f,0wx682e6ff3,0wx748f82ee,0wx78a5636f,0wx84c87814,0wx8cc70208,
     0wx90befffa,0wxa4506ceb,0wxbef9a3f7,0wxc67178f2]

  fun padded (msg : string) : Word32.word list =
    let
      val len = String.size msg
      val bitLen = IntInf.fromInt len * 8
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
        let fun b (kk : int) = Word32.fromInt (Char.ord (String.sub (full, i + kk)))
        in (b 0 << 0w24) orb (b 1 << 0w16) orb (b 2 << 0w8) orb (b 3) end
      fun loop (i : int) acc = if i >= n then List.rev acc else loop (i + 4) (word i :: acc)
    in
      loop 0 []
    end

  fun chunk16 ws =
    case ws of
        [] => []
      | _ =>
          let
            fun take 0 xs acc = (List.rev acc, xs)
              | take (j : int) (x :: xs) acc = take (j - 1) xs (x :: acc)
              | take _ [] acc = (List.rev acc, [])
            val (blk, rest) = take 16 ws []
          in blk :: chunk16 rest end

  fun processBlock ((h0,h1,h2,h3,h4,h5,h6,h7), block) =
    let
      val w = Array.array (64, 0w0 : Word32.word)
      val _ = List.foldl (fn (x, i) => (Array.update (w, i, x); i + 1)) 0 block
      fun extend (i : int) =
        if i >= 64 then ()
        else
          let
            val w15 = Array.sub (w, i-15)
            val w2  = Array.sub (w, i-2)
            val s0 = rotr (w15, 7) xorb rotr (w15, 18) xorb (w15 >> 0w3)
            val s1 = rotr (w2, 17) xorb rotr (w2, 19) xorb (w2 >> 0w10)
          in
            Array.update (w, i, Array.sub (w, i-16) ++ s0 ++ Array.sub (w, i-7) ++ s1);
            extend (i + 1)
          end
      val () = extend 16

      fun round (i : int, a, b, c, d, e, f, g, h) =
        if i >= 64 then (a,b,c,d,e,f,g,h)
        else
          let
            val s1 = rotr (e, 6) xorb rotr (e, 11) xorb rotr (e, 25)
            val ch = (e andb f) xorb ((notb e) andb g)
            val t1 = h ++ s1 ++ ch ++ Vector.sub (k, i) ++ Array.sub (w, i)
            val s0 = rotr (a, 2) xorb rotr (a, 13) xorb rotr (a, 22)
            val maj = (a andb b) xorb (a andb c) xorb (b andb c)
            val t2 = s0 ++ maj
          in
            round (i + 1, t1 ++ t2, a, b, c, d ++ t1, e, f, g)
          end
      val (a,b,c,d,e,f,g,h) = round (0, h0,h1,h2,h3,h4,h5,h6,h7)
    in
      (h0 ++ a, h1 ++ b, h2 ++ c, h3 ++ d, h4 ++ e, h5 ++ f, h6 ++ g, h7 ++ h)
    end

  fun digestWords msg =
    let
      val blocks = chunk16 (padded msg)
      val init = (0wx6a09e667,0wxbb67ae85,0wx3c6ef372,0wxa54ff53a,
                  0wx510e527f,0wx9b05688c,0wx1f83d9ab,0wx5be0cd19)
    in
      List.foldl (fn (blk, st) => processBlock (st, blk)) init blocks
    end

  fun wordBytes w =
    String.implode
      (List.map
        (fn (sh : int) => Char.chr (Word32.toInt ((w >> Word.fromInt sh) andb 0wxFF)))
        [24, 16, 8, 0])

  fun toList (a,b,c,d,e,f,g,h) = [a,b,c,d,e,f,g,h]

  fun digest msg =
    String.concat (List.map wordBytes (toList (digestWords msg)))

  fun hexDigest msg =
    let fun hex w = StringCvt.padLeft #"0" 8 (Word32.fmt StringCvt.HEX w)
    in String.map Char.toLower
         (String.concat (List.map hex (toList (digestWords msg)))) end
end
