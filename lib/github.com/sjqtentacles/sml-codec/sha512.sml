(* sha512.sml

   SHA-512 over a byte string, all arithmetic on Word64.word. Padding uses a
   128-bit big-endian length field (we only handle messages < 2^61 bytes).
   The implementation is byte-identical on MLton and Poly/ML. *)

structure Sha512 :> SHA512 =
struct
  val k64 : Word64.word array = Array.fromList
    [ 0wx428a2f98d728ae22, 0wx7137449123ef65cd
    , 0wxb5c0fbcfec4d3b2f, 0wxe9b5dba58189dbbc
    , 0wx3956c25bf348b538, 0wx59f111f1b605d019
    , 0wx923f82a4af194f9b, 0wxab1c5ed5da6d8118
    , 0wxd807aa98a3030242, 0wx12835b0145706fbe
    , 0wx243185be4ee4b28c, 0wx550c7dc3d5ffb4e2
    , 0wx72be5d74f27b896f, 0wx80deb1fe3b1696b1
    , 0wx9bdc06a725c71235, 0wxc19bf174cf692694
    , 0wxe49b69c19ef14ad2, 0wxefbe4786384f25e3
    , 0wx0fc19dc68b8cd5b5, 0wx240ca1cc77ac9c65
    , 0wx2de92c6f592b0275, 0wx4a7484aa6ea6e483
    , 0wx5cb0a9dcbd41fbd4, 0wx76f988da831153b5
    , 0wx983e5152ee66dfab, 0wxa831c66d2db43210
    , 0wxb00327c898fb213f, 0wxbf597fc7beef0ee4
    , 0wxc6e00bf33da88fc2, 0wxd5a79147930aa725
    , 0wx06ca6351e003826f, 0wx142929670a0e6e70
    , 0wx27b70a8546d22ffc, 0wx2e1b21385c26c926
    , 0wx4d2c6dfc5ac42aed, 0wx53380d139d95b3df
    , 0wx650a73548baf63de, 0wx766a0abb3c77b2a8
    , 0wx81c2c92e47edaee6, 0wx92722c851482353b
    , 0wxa2bfe8a14cf10364, 0wxa81a664bbc423001
    , 0wxc24b8b70d0f89791, 0wxc76c51a30654be30
    , 0wxd192e819d6ef5218, 0wxd69906245565a910
    , 0wxf40e35855771202a, 0wx106aa07032bbd1b8
    , 0wx19a4c116b8d2d0c8, 0wx1e376c085141ab53
    , 0wx2748774cdf8eeb99, 0wx34b0bcb5e19b48a8
    , 0wx391c0cb3c5c95a63, 0wx4ed8aa4ae3418acb
    , 0wx5b9cca4f7763e373, 0wx682e6ff3d6b2b8a3
    , 0wx748f82ee5defb2fc, 0wx78a5636f43172f60
    , 0wx84c87814a1f0ab72, 0wx8cc702081a6439ec
    , 0wx90befffa23631e28, 0wxa4506cebde82bde9
    , 0wxbef9a3f7b2c67915, 0wxc67178f2e372532b
    , 0wxca273eceea26619c, 0wxd186b8c721c0c207
    , 0wxeada7dd6cde0eb1e, 0wxf57d4f7fee6ed178
    , 0wx06f067aa72176fba, 0wx0a637dc5a2c898a6
    , 0wx113f9804bef90dae, 0wx1b710b35131c471b
    , 0wx28db77f523047d84, 0wx32caab7b40c72493
    , 0wx3c9ebe0a15c9bebc, 0wx431d67c49c100d4c
    , 0wx4cc5d4becb3e42b6, 0wx597f299cfc657e2a
    , 0wx5fcb6fab3ad6faec, 0wx6c44198c4a475817 ]

  fun rotr (x : Word64.word) (n : Word.word) : Word64.word =
    Word64.orb (Word64.>> (x, n), Word64.<< (x, 0w64 - n))

  fun getBE64 (s : string) (off : int) : Word64.word =
    List.foldl (fn (i, acc) =>
      Word64.orb (Word64.<< (acc, 0w8),
                  Word64.fromInt (Char.ord (String.sub (s, off + i)))))
      0w0 (List.tabulate (8, fn i => i))

  fun compress (hv : Word64.word array) (blk : string) (off : int) : unit =
    let
      val w = Array.array (80, 0w0 : Word64.word)
      val () = List.app (fn i => Array.update (w, i, getBE64 blk (off + i*8)))
                        (List.tabulate (16, fn i => i))
      val () = List.app (fn i =>
          let
            val s0 = Word64.xorb (Word64.xorb
                       (rotr (Array.sub (w, i-15)) 0w1,
                        rotr (Array.sub (w, i-15)) 0w8),
                        Word64.>> (Array.sub (w, i-15), 0w7))
            val s1 = Word64.xorb (Word64.xorb
                       (rotr (Array.sub (w, i-2)) 0w19,
                        rotr (Array.sub (w, i-2)) 0w61),
                        Word64.>> (Array.sub (w, i-2), 0w6))
          in
            Array.update (w, i, Word64.+ (Word64.+ (Word64.+
              (Array.sub (w, i-16), s0), Array.sub (w, i-7)), s1))
          end)
        (List.tabulate (64, fn i => i + 16))

      val vars = Array.tabulate (8, fn i => ref (Array.sub (hv, i)))
      fun v i = Array.sub (vars, i)

      val () = List.app (fn i =>
          let
            val e  = !(v 4)
            val s1 = Word64.xorb (Word64.xorb
                       (rotr e 0w14, rotr e 0w18), rotr e 0w41)
            val ch = Word64.xorb
                       (Word64.andb (e, !(v 5)),
                        Word64.andb (Word64.notb e, !(v 6)))
            val t1 = Word64.+ (Word64.+ (Word64.+ (Word64.+
                       (!(v 7), s1), ch), Array.sub (k64, i)), Array.sub (w, i))
            val a  = !(v 0)
            val s0 = Word64.xorb (Word64.xorb
                       (rotr a 0w28, rotr a 0w34), rotr a 0w39)
            val maj = Word64.xorb (Word64.xorb
                        (Word64.andb (a, !(v 1)),
                         Word64.andb (a, !(v 2))),
                         Word64.andb (!(v 1), !(v 2)))
            val t2 = Word64.+ (s0, maj)
          in
            ( v 7 := !(v 6)
            ; v 6 := !(v 5)
            ; v 5 := !(v 4)
            ; v 4 := Word64.+ (!(v 3), t1)
            ; v 3 := !(v 2)
            ; v 2 := !(v 1)
            ; v 1 := !(v 0)
            ; v 0 := Word64.+ (t1, t2) )
          end)
        (List.tabulate (80, fn i => i))

      val () = List.app (fn i =>
          Array.update (hv, i, Word64.+ (Array.sub (hv, i), !(Array.sub (vars, i)))))
        (List.tabulate (8, fn i => i))
    in () end

  fun digestWords (msg : string) : Word64.word array =
    let
      val hv = Array.fromList
        [ 0wx6a09e667f3bcc908, 0wxbb67ae8584caa73b
        , 0wx3c6ef372fe94f82b, 0wxa54ff53a5f1d36f1
        , 0wx510e527fade682d1, 0wx9b05688c2b3e6c1f
        , 0wx1f83d9abfb41bd6b, 0wx5be0cd19137e2179 ]
      val mlen   = String.size msg
      val bitlen = mlen * 8
      (* Padding: 0x80, zeros, 16-byte BE length (we only handle mlen < 2^61) *)
      val pad1   = String.str (Char.chr 128)
      val fill   = (112 - (mlen + 1) mod 128 + 128) mod 128
      val zeros  = String.implode (List.tabulate (fill, fn _ => #"\000"))
      (* High 8 bytes of 128-bit length = 0; low 8 bytes = bitlen *)
      val lenhi  = "\000\000\000\000\000\000\000\000"
      val lenlo  = String.implode (List.tabulate (8, fn i =>
                     Char.chr (Word64.toInt (Word64.andb
                       (Word64.>> (Word64.fromInt bitlen,
                                   Word.fromInt (56 - i*8)), 0wxff)))))
      val padded = msg ^ pad1 ^ zeros ^ lenhi ^ lenlo
      val nblk   = String.size padded div 128
      val () = List.app (fn b => compress hv padded (b * 128))
                        (List.tabulate (nblk, fn i => i))
    in
      hv
    end

  fun wordBytes (w : Word64.word) : string =
    String.implode (List.tabulate (8, fn i =>
      Char.chr (Word64.toInt (Word64.andb
        (Word64.>> (w, Word.fromInt (56 - i*8)), 0wxff)))))

  fun digest msg =
    let val hv = digestWords msg
    in String.concat (List.tabulate (8, fn i => wordBytes (Array.sub (hv, i)))) end

  fun hexDigest msg =
    let
      val hv = digestWords msg
      fun hex w = StringCvt.padLeft #"0" 16 (Word64.fmt StringCvt.HEX w)
    in
      String.map Char.toLower
        (String.concat (List.tabulate (8, fn i => hex (Array.sub (hv, i)))))
    end
end
