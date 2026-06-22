(* crc32.sml *)

structure Crc32 :> CRC32 =
struct
  val andb = Word32.andb
  val xorb = Word32.xorb
  infix 5 andb
  infix 4 xorb
  fun >> (a, b) = Word32.>> (a, b)
  infix 6 >>

  val poly : Word32.word = 0wxEDB88320

  (* Precompute the 256-entry lookup table once. *)
  val table : Word32.word vector =
    Vector.tabulate (256, fn n =>
      let
        fun step (c, k : int) =
          if k = 0 then c
          else
            let
              val c' = if (c andb 0w1) <> 0w0
                       then poly xorb (c >> 0w1)
                       else c >> 0w1
            in step (c', k - 1) end
      in
        step (Word32.fromInt n, 8)
      end)

  fun crc s =
    let
      val init : Word32.word = 0wxFFFFFFFF
      fun upd (c, byte) =
        let
          val idx = Word32.toInt ((c xorb Word32.fromInt (Char.ord byte)) andb 0wxFF)
        in
          Vector.sub (table, idx) xorb (c >> 0w8)
        end
      val final = CharVector.foldl (fn (ch, acc) => upd (acc, ch)) init s
    in
      final xorb 0wxFFFFFFFF
    end

  fun crcHex s =
    let val w = crc s
    in String.map Char.toLower (StringCvt.padLeft #"0" 8 (Word32.fmt StringCvt.HEX w)) end
end
