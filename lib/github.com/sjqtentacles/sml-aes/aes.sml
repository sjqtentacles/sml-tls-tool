(* aes.sml - AES block cipher (FIPS 197) + CBC, CTR, GCM modes. *)

(* Shared utilities *)
local
  val sboxV : Word8.word array = Array.fromList (List.map Word8.fromInt
    [ 99,124,119,123,242,107,111,197, 48,  1,103, 43,254,215,171,118
    ,202,130,201,125,250, 89, 71,240,173,212,162,175,156,164,114,192
    ,183,253,147, 38, 54, 63,247,204, 52,165,229,241,113,216, 49, 21
    ,  4,199, 35,195, 24,150,  5,154,  7, 18,128,226,235, 39,178,117
    ,  9,131, 44, 26, 27,110, 90,160, 82, 59,214,179, 41,227, 47,132
    , 83,209,  0,237, 32,252,177, 91,106,203,190, 57, 74, 76, 88,207
    ,208,239,170,251, 67, 77, 51,133, 69,249,  2,127, 80, 60,159,168
    , 81,163, 64,143,146,157, 56,245,188,182,218, 33, 16,255,243,210
    ,205, 12, 19,236, 95,151, 68, 23,196,167,126, 61,100, 93, 25,115
    , 96,129, 79,220, 34, 42,144,136, 70,238,184, 20,222, 94, 11,219
    ,224, 50, 58, 10, 73,  6, 36, 92,194,211,172, 98,145,149,228,121
    ,231,200, 55,109,141,213, 78,169,108, 86,244,234,101,122,174,  8
    ,186,120, 37, 46, 28,166,180,198,232,221,116, 31, 75,189,139,138
    ,112, 62,181,102, 72,  3,246, 14, 97, 53, 87,185,134,193, 29,158
    ,225,248,152, 17,105,217,142,148,155, 30,135,233,206, 85, 40,223
    ,140,161,137, 13,191,230, 66,104, 65,153, 45, 15,176, 84,187, 22 ])

  val sboxInvV : Word8.word array = Array.fromList (List.map Word8.fromInt
    [ 82,  9,106,213, 48, 54,165, 56,191, 64,163,158,129,243,215,251
    ,124,227, 57,130,155, 47,255,135, 52,142, 67, 68,196,222,233,203
    , 84,123,148, 50,166,194, 35, 61,238, 76,149, 11, 66,250,195, 78
    ,  8, 46,161,102, 40,217, 36,178,118, 91,162, 73,109,139,209, 37
    ,114,248,246,100,134,104,152, 22,212,164, 92,204, 93,101,182,146
    ,108,112, 72, 80,253,237,185,218, 94, 21, 70, 87,167,141,157,132
    ,144,216,171,  0,140,188,211, 10,247,228, 88,  5,184,179, 69,  6
    ,208, 44, 30,143,202, 63, 15,  2,193,175,189,  3,  1, 19,138,107
    , 58,145, 17, 65, 79,103,220,234,151,242,207,206,240,180,230,115
    ,150,172,116, 34,231,173, 53,133,226,249, 55,232, 28,117,223,110
    , 71,241, 26,113, 29, 41,197,137,111,183, 98, 14,170, 24,190, 27
    ,252, 86, 62, 75,198,210,121, 32,154,219,192,254,120,205, 90,244
    , 31,221,168, 51,136,  7,199, 49,177, 18, 16, 89, 39,128,236, 95
    , 96, 81,127,169, 25,181, 74, 13, 45,229,122,159,147,201,156,239
    ,160,224, 59, 77,174, 42,245,176,200,235,187, 60,131, 83,153, 97
    , 23, 43,  4,126,186,119,214, 38,225,105, 20, 99, 85, 33, 12,125 ])

  fun xt (b : Word8.word) : Word8.word =
    let val s = Word8.<< (b, 0w1)
    in if Word8.andb (b, 0wx80) <> 0w0
       then Word8.xorb (s, 0wx1b) else s
    end

  fun gm (a : Word8.word) (b : Word8.word) : Word8.word =
    let
      fun go 0 _ _ acc = acc
        | go n a b acc =
            let val acc' = if Word8.andb (b, 0w1) <> 0w0 then Word8.xorb (acc, a) else acc
            in go (n-1) (xt a) (Word8.>> (b, 0w1)) acc' end
    in go 8 a b 0w0 end

  val rc : Word8.word array = Array.fromList (List.map Word8.fromInt
    [1,2,4,8,16,32,64,128,27,54])

  fun subW (w : Word32.word) : Word32.word =
    let fun s n = Word32.fromInt (Word8.toInt (Array.sub (sboxV,
                    Word32.toInt (Word32.andb (Word32.>> (w, Word.fromInt n), 0wxff)))))
    in Word32.orb (Word32.orb (Word32.orb
         (Word32.<< (s 24, 0w24), Word32.<< (s 16, 0w16)),
          Word32.<< (s 8, 0w8)), s 0)
    end

  fun rotW (w : Word32.word) : Word32.word =
    Word32.orb (Word32.<< (w, 0w8), Word32.>> (w, 0w24))

  fun getW32 (s : string) (off : int) : Word32.word =
    Word32.orb (Word32.orb (Word32.orb
      (Word32.<< (Word32.fromInt (Char.ord (String.sub (s, off))),   0w24),
       Word32.<< (Word32.fromInt (Char.ord (String.sub (s, off+1))), 0w16)),
       Word32.<< (Word32.fromInt (Char.ord (String.sub (s, off+2))), 0w8)),
       Word32.fromInt (Char.ord (String.sub (s, off+3))))

  fun putW32 (w : Word32.word) : string =
    let fun b n = Char.chr (Word32.toInt (Word32.andb (Word32.>> (w, Word.fromInt n), 0wxff)))
    in String.implode [b 24, b 16, b 8, b 0] end

  fun xorBytes (a : string) (b : string) : string =
    String.implode (List.tabulate (String.size a, fn i =>
      Char.chr (Word8.toInt (Word8.xorb
        (Word8.fromInt (Char.ord (String.sub (a, i))),
         Word8.fromInt (Char.ord (String.sub (b, i))))))))
in
  val sboxV    = sboxV
  val sboxInvV = sboxInvV
  val gm       = gm
  val rc       = rc
  val subW     = subW
  val rotW     = rotW
  val getW32   = getW32
  val putW32   = putW32
  val xorBytes = xorBytes
end

(* ------------------------------------------------------------------ *)
(* AES block cipher core                                                *)
(* ------------------------------------------------------------------ *)

structure AesBlock : AES_BLOCK =
struct
  type key = { nr: int, w: Word32.word array }

  fun keySize ({nr, ...} : key) = (nr - 6) * 4

  fun expandKey (keyBytes : string) (nk : int) : key =
    let
      val nr = nk + 6
      val total = (nr + 1) * 4
      val w = Array.array (total, 0w0 : Word32.word)
      val () = List.app (fn i => Array.update (w, i, getW32 keyBytes (i*4)))
                        (List.tabulate (nk, fn i => i))
      val () = List.app (fn i =>
          let val prev = Array.sub (w, i-1)
              val temp =
                if i mod nk = 0 then
                  Word32.xorb (subW (rotW prev),
                    Word32.<< (Word32.fromInt (Word8.toInt (Array.sub (rc, i div nk - 1))), 0w24))
                else if nk > 6 andalso i mod nk = 4 then subW prev
                else prev
          in Array.update (w, i, Word32.xorb (Array.sub (w, i-nk), temp)) end)
        (List.tabulate (total - nk, fn i => i + nk))
    in {nr = nr, w = w} end

  fun expand128 k = expandKey k 4
  fun expand192 k = expandKey k 6
  fun expand256 k = expandKey k 8

  (* State: 4 columns x 4 rows, stored column-major in a 16-element array *)
  fun blockToState (b : string) : Word8.word array =
    Array.tabulate (16, fn i => Word8.fromInt (Char.ord (String.sub (b, i))))

  fun stateToBlock (s : Word8.word array) : string =
    String.implode (List.tabulate (16, fn i => Char.chr (Word8.toInt (Array.sub (s, i)))))

  fun addRK (st : Word8.word array) (w : Word32.word array) (round : int) : unit =
    List.app (fn c =>
      let val word = Array.sub (w, round*4 + c)
          fun b n = Word8.fromInt (Word32.toInt (Word32.andb (Word32.>> (word, Word.fromInt n), 0wxff)))
      in
        Array.update (st, c*4+0, Word8.xorb (Array.sub (st, c*4+0), b 24));
        Array.update (st, c*4+1, Word8.xorb (Array.sub (st, c*4+1), b 16));
        Array.update (st, c*4+2, Word8.xorb (Array.sub (st, c*4+2), b 8));
        Array.update (st, c*4+3, Word8.xorb (Array.sub (st, c*4+3), b 0))
      end)
    [0,1,2,3]

  fun subB  st = List.app (fn i => Array.update (st, i, Array.sub (sboxV,    Word8.toInt (Array.sub (st, i))))) (List.tabulate (16, fn i => i))
  fun subBi st = List.app (fn i => Array.update (st, i, Array.sub (sboxInvV, Word8.toInt (Array.sub (st, i))))) (List.tabulate (16, fn i => i))

  fun shiftR (st : Word8.word array) : unit =
    let
      fun getRow r = List.tabulate (4, fn c => Array.sub (st, c*4 + r))
      fun setRow r xs = List.app (fn (c,v) => Array.update (st, c*4+r, v)) (ListPair.zip ([0,1,2,3], xs))
      val r1 = getRow 1  val r2 = getRow 2  val r3 = getRow 3
    in
      setRow 1 [List.nth(r1,1), List.nth(r1,2), List.nth(r1,3), List.nth(r1,0)];
      setRow 2 [List.nth(r2,2), List.nth(r2,3), List.nth(r2,0), List.nth(r2,1)];
      setRow 3 [List.nth(r3,3), List.nth(r3,0), List.nth(r3,1), List.nth(r3,2)]
    end

  fun shiftRi (st : Word8.word array) : unit =
    let
      fun getRow r = List.tabulate (4, fn c => Array.sub (st, c*4 + r))
      fun setRow r xs = List.app (fn (c,v) => Array.update (st, c*4+r, v)) (ListPair.zip ([0,1,2,3], xs))
      val r1 = getRow 1  val r2 = getRow 2  val r3 = getRow 3
    in
      setRow 1 [List.nth(r1,3), List.nth(r1,0), List.nth(r1,1), List.nth(r1,2)];
      setRow 2 [List.nth(r2,2), List.nth(r2,3), List.nth(r2,0), List.nth(r2,1)];
      setRow 3 [List.nth(r3,1), List.nth(r3,2), List.nth(r3,3), List.nth(r3,0)]
    end

  fun mixC (st : Word8.word array) (c : int) : unit =
    let val off = c*4
        val s0 = Array.sub (st,off) val s1 = Array.sub (st,off+1)
        val s2 = Array.sub (st,off+2) val s3 = Array.sub (st,off+3)
    in
      Array.update (st,off,  Word8.xorb(Word8.xorb(Word8.xorb(gm 0w2 s0, gm 0w3 s1), s2), s3));
      Array.update (st,off+1,Word8.xorb(Word8.xorb(Word8.xorb(s0, gm 0w2 s1), gm 0w3 s2), s3));
      Array.update (st,off+2,Word8.xorb(Word8.xorb(Word8.xorb(s0, s1), gm 0w2 s2), gm 0w3 s3));
      Array.update (st,off+3,Word8.xorb(Word8.xorb(Word8.xorb(gm 0w3 s0, s1), s2), gm 0w2 s3))
    end

  fun mixCi (st : Word8.word array) (c : int) : unit =
    let val off = c*4
        val s0 = Array.sub (st,off) val s1 = Array.sub (st,off+1)
        val s2 = Array.sub (st,off+2) val s3 = Array.sub (st,off+3)
    in
      Array.update (st,off,  Word8.xorb(Word8.xorb(Word8.xorb(gm 0w14 s0, gm 0w11 s1), gm 0w13 s2), gm 0w9 s3));
      Array.update (st,off+1,Word8.xorb(Word8.xorb(Word8.xorb(gm 0w9 s0, gm 0w14 s1), gm 0w11 s2), gm 0w13 s3));
      Array.update (st,off+2,Word8.xorb(Word8.xorb(Word8.xorb(gm 0w13 s0, gm 0w9 s1), gm 0w14 s2), gm 0w11 s3));
      Array.update (st,off+3,Word8.xorb(Word8.xorb(Word8.xorb(gm 0w11 s0, gm 0w13 s1), gm 0w9 s2), gm 0w14 s3))
    end

  fun encrypt ({nr, w} : key) (blk : string) : string =
    let
      val st = blockToState blk
      val () = addRK st w 0
      val () = List.app (fn r =>
          ( subB st; shiftR st
          ; if r < nr then List.app (mixC st) [0,1,2,3] else ()
          ; addRK st w r ))
        (List.tabulate (nr, fn i => i+1))
    in stateToBlock st end

  fun decrypt ({nr, w} : key) (blk : string) : string =
    let
      val st = blockToState blk
      val () = addRK st w nr
      val () = List.app (fn i =>
          let val r = nr - i
          in ( shiftRi st; subBi st; addRK st w r
             ; if r > 0 then List.app (mixCi st) [0,1,2,3] else () )
          end)
        (List.tabulate (nr, fn i => i+1))
    in stateToBlock st end
end

(* ------------------------------------------------------------------ *)
(* AES-ECB mode                                                         *)
(* ------------------------------------------------------------------ *)

structure AesEcb : AES_MODE =
struct
  fun encrypt (keyBytes : string) (_ : string) (pt : string) : string =
    let val key = if String.size keyBytes = 16 then AesBlock.expand128 keyBytes
                  else if String.size keyBytes = 24 then AesBlock.expand192 keyBytes
                  else AesBlock.expand256 keyBytes
        val n = String.size pt div 16
    in String.concat (List.tabulate (n, fn i =>
         AesBlock.encrypt key (String.substring (pt, i*16, 16)))) end

  fun decrypt (keyBytes : string) (_ : string) (ct : string) : string =
    let val key = if String.size keyBytes = 16 then AesBlock.expand128 keyBytes
                  else if String.size keyBytes = 24 then AesBlock.expand192 keyBytes
                  else AesBlock.expand256 keyBytes
        val n = String.size ct div 16
    in String.concat (List.tabulate (n, fn i =>
         AesBlock.decrypt key (String.substring (ct, i*16, 16)))) end
end

(* ------------------------------------------------------------------ *)
(* AES-CBC mode                                                         *)
(* ------------------------------------------------------------------ *)

structure AesCbc : AES_MODE =
struct
  fun encrypt (keyBytes : string) (iv : string) (pt : string) : string =
    let val key = if String.size keyBytes = 16 then AesBlock.expand128 keyBytes
                  else if String.size keyBytes = 24 then AesBlock.expand192 keyBytes
                  else AesBlock.expand256 keyBytes
        val n = String.size pt div 16
    in #2 (List.foldl (fn (i, (prev, acc)) =>
         let val blk = String.substring (pt, i*16, 16)
             val ct  = AesBlock.encrypt key (xorBytes prev blk)
         in (ct, acc ^ ct) end)
       (iv, "")
       (List.tabulate (n, fn i => i))) end

  fun decrypt (keyBytes : string) (iv : string) (ct : string) : string =
    let val key = if String.size keyBytes = 16 then AesBlock.expand128 keyBytes
                  else if String.size keyBytes = 24 then AesBlock.expand192 keyBytes
                  else AesBlock.expand256 keyBytes
        val n = String.size ct div 16
    in #2 (List.foldl (fn (i, (prev, acc)) =>
         let val blk = String.substring (ct, i*16, 16)
             val pt  = xorBytes (AesBlock.decrypt key blk) prev
         in (blk, acc ^ pt) end)
       (iv, "")
       (List.tabulate (n, fn i => i))) end
end

(* ------------------------------------------------------------------ *)
(* AES-CTR mode                                                         *)
(* ------------------------------------------------------------------ *)

structure AesCtr : AES_MODE =
struct
  fun incCtr (ctr : string) : string =
    let
      val bytes = Array.tabulate (16, fn i => Char.ord (String.sub (ctr, i)))
      fun inc i =
        if i < 0 then ()
        else let val v = (Array.sub (bytes, i) + 1) mod 256
             in Array.update (bytes, i, v);
                if v = 0 then inc (i-1) else () end
    in
      inc 15;
      String.implode (List.tabulate (16, fn i => Char.chr (Array.sub (bytes, i))))
    end

  fun xorStream (keyBytes : string) (iv : string) (data : string) : string =
    let val key = if String.size keyBytes = 16 then AesBlock.expand128 keyBytes
                  else if String.size keyBytes = 24 then AesBlock.expand192 keyBytes
                  else AesBlock.expand256 keyBytes
        val n    = String.size data
        val nblk = (n + 15) div 16
        val buf  = Array.array (n, #"\000")
        val ctr  = ref iv
        val ()   = List.app (fn b =>
            let val ks = AesBlock.encrypt key (!ctr)
                val _  = ctr := incCtr (!ctr)
                val sz = Int.min (16, n - b*16)
            in List.app (fn i =>
                 Array.update (buf, b*16+i,
                   Char.chr (Word8.toInt (Word8.xorb
                     (Word8.fromInt (Char.ord (String.sub (data, b*16+i))),
                      Word8.fromInt (Char.ord (String.sub (ks, i))))))))
               (List.tabulate (sz, fn i => i))
            end)
          (List.tabulate (nblk, fn i => i))
    in String.implode (Array.foldr (op ::) [] buf) end

  fun encrypt k iv pt = xorStream k iv pt
  fun decrypt k iv ct = xorStream k iv ct
end

(* ------------------------------------------------------------------ *)
(* AES-GCM AEAD                                                         *)
(* ------------------------------------------------------------------ *)

structure AesGcm : AES_GCM =
struct
  (* GHASH: GF(2^128) multiply; polynomial x^128+x^7+x^2+x+1 *)
  fun ghashMul (x : string) (y : string) : string =
    let
      val z = Array.array (16, 0w0 : Word8.word)
      val v = Array.tabulate (16, fn i => Word8.fromInt (Char.ord (String.sub (y, i))))
      val () = List.app (fn i =>
          List.app (fn j =>
            let val bit = Word8.andb (Word8.>> (Word8.fromInt (Char.ord (String.sub (x, i))),
                                                Word.fromInt (7 - j)), 0w1) <> 0w0
            in
              if bit then
                List.app (fn k => Array.update (z, k, Word8.xorb (Array.sub (z, k), Array.sub (v, k))))
                  (List.tabulate (16, fn k => k))
              else ();
              (* v := v >> 1 in GF(2^128). V is a 128-bit value stored
                 big-endian across 16 bytes (byte 0 = most significant), and a
                 one-bit right shift moves bit i to bit i+1, so each byte's new
                 high bit is the old LOW bit of the more-significant neighbour
                 (byte k-1). Iterate k high->low so v[k-1] is still the old
                 value when read. The bit shifted out is the LSB of byte 15. *)
              let val outBit = Word8.andb (Array.sub (v, 15), 0w1) <> 0w0
              in
                List.app (fn k =>
                  Array.update (v, k,
                    Word8.orb (
                      Word8.>> (Array.sub (v, k), 0w1),
                      if k > 0 then Word8.<< (Word8.andb (Array.sub (v, k-1), 0w1), 0w7)
                      else 0w0)))
                  (List.rev (List.tabulate (16, fn k => k)));
                if outBit then Array.update (v, 0, Word8.xorb (Array.sub (v, 0), 0wxe1))
                else ()
              end
            end)
          (List.tabulate (8, fn j => j)))
        (List.tabulate (16, fn i => i))
    in
      String.implode (List.tabulate (16, fn i => Char.chr (Word8.toInt (Array.sub (z, i)))))
    end

  fun ghash (h : string) (aad : string) (ct : string) : string =
    let
      fun padTo16 s =
        let val n = String.size s
            val pad = (16 - n mod 16) mod 16
        in s ^ String.implode (List.tabulate (pad, fn _ => #"\000")) end

      fun le64 n =
        String.implode (List.tabulate (8, fn i =>
          Char.chr (Word8.toInt (Word8.andb
            (Word8.fromInt (IntInf.toInt (IntInf.andb
              (IntInf.div (IntInf.fromInt n, IntInf.<< (IntInf.fromInt 1, Word.fromInt (56 - i*8))),
               IntInf.fromInt 255))),
             0wxff)))))

      val data = padTo16 aad ^ padTo16 ct ^
                 le64 (String.size aad * 8) ^ le64 (String.size ct * 8)
      val nblk = String.size data div 16
    in
      List.foldl (fn (i, y) =>
        ghashMul (xorBytes y (String.substring (data, i*16, 16))) h)
      (String.implode (List.tabulate (16, fn _ => #"\000")))
      (List.tabulate (nblk, fn i => i))
    end

  fun incCtr32 (ctr : string) : string =
    let
      val bytes = Array.tabulate (16, fn i => Char.ord (String.sub (ctr, i)))
      fun inc i =
        if i < 12 then ()
        else let val v = (Array.sub (bytes, i) + 1) mod 256
             in Array.update (bytes, i, v);
                if v = 0 then inc (i-1) else () end
    in
      inc 15;
      String.implode (List.tabulate (16, fn i => Char.chr (Array.sub (bytes, i))))
    end

  fun seal (keyBytes : string) (iv : string) (aad : string) (pt : string) : string =
    let val key   = if String.size keyBytes = 16 then AesBlock.expand128 keyBytes
                    else if String.size keyBytes = 24 then AesBlock.expand192 keyBytes
                    else AesBlock.expand256 keyBytes
        val h     = AesBlock.encrypt key (String.implode (List.tabulate (16, fn _ => #"\000")))
        val j0    = iv ^ "\000\000\000\001"
        val ct    = AesCtr.encrypt keyBytes (incCtr32 j0) pt
        val tag0  = AesBlock.encrypt key j0
        val s     = ghash h aad ct
        val tag   = xorBytes s tag0
    in ct ^ tag end

  fun open' (keyBytes : string) (iv : string) (aad : string) (sealed : string) : string option =
    let val slen = String.size sealed
    in if slen < 16 then NONE
       else let
         val ct  = String.substring (sealed, 0, slen - 16)
         val tag = String.substring (sealed, slen - 16, 16)
         val key = if String.size keyBytes = 16 then AesBlock.expand128 keyBytes
                   else if String.size keyBytes = 24 then AesBlock.expand192 keyBytes
                   else AesBlock.expand256 keyBytes
         val h    = AesBlock.encrypt key (String.implode (List.tabulate (16, fn _ => #"\000")))
         val j0   = iv ^ "\000\000\000\001"
         val s    = ghash h aad ct
         val expected = xorBytes s (AesBlock.encrypt key j0)
         val ok   = List.foldl (fn ((a,b), acc) => acc andalso a = b) true
                      (ListPair.zip (String.explode expected, String.explode tag))
       in if ok then SOME (AesCtr.decrypt keyBytes (incCtr32 j0) ct)
          else NONE
       end
    end
end
