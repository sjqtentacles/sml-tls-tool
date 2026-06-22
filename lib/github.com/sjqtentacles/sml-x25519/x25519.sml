(* x25519.sml
 *
 * Curve25519 Diffie-Hellman key exchange (RFC 7748).
 *
 * Field is GF(2^255 - 19).  All field arithmetic is done with IntInf.int,
 * which is arbitrary precision in the Basis, so there are no overflow
 * concerns and the code is portable across MLton and Poly/ML.
 *
 * Inputs and outputs are little-endian 32-byte strings (one char = one byte).
 *)
structure X25519 :> X25519 =
struct

  val keySize = 32

  (* ----- byte string <-> IntInf helpers ----- *)

  fun byteAt (s, i) = IntInf.fromInt (Char.ord (String.sub (s, i)))

  (* require exactly 32 bytes *)
  fun require32 s =
    if String.size s <> keySize
    then raise Fail ("X25519: expected " ^ Int.toString keySize ^ " bytes, got "
                     ^ Int.toString (String.size s))
    else ()

  (* little-endian decode of a 32-byte string into an IntInf *)
  fun leDecode s =
    let
      fun loop (i, acc) =
        if i < 0 then acc
        else loop (i - 1, acc * 0x100 + byteAt (s, i))
    in
      loop (keySize - 1, 0 : IntInf.int)
    end

  (* little-endian encode an IntInf into a 32-byte string *)
  fun leEncode (n : IntInf.int) =
    let
      fun byte i =
        Char.chr (IntInf.toInt (IntInf.andb (IntInf.~>> (n, Word.fromInt (8 * i)), 0xFF)))
    in
      CharVector.tabulate (keySize, byte)
    end

  (* ----- scalar clamping (RFC 7748 section 5) ----- *)

  fun clamp s =
    let
      val () = require32 s
      fun mapByte i =
        let val b = Char.ord (String.sub (s, i))
        in
          if i = 0 then Char.chr (Word.toInt (Word.andb (Word.fromInt b, 0wxF8)))
          else if i = 31 then
            Char.chr (Word.toInt (Word.orb (Word.andb (Word.fromInt b, 0wx7F), 0wx40)))
          else Char.chr b
        end
    in
      CharVector.tabulate (keySize, mapByte)
    end

  (* ----- field arithmetic mod p = 2^255 - 19 ----- *)

  val p : IntInf.int = IntInf.<< (1, 0w255) - 19

  fun fadd (a, b) = (a + b) mod p
  fun fsub (a, b) = ((a - b) mod p + p) mod p
  fun fmul (a, b) = (a * b) mod p

  (* modular inverse via Fermat: a^(p-2) mod p *)
  fun fpow (base, e) =
    let
      fun loop (b, e, acc) =
        if e = 0 then acc
        else
          let val acc = if IntInf.andb (e, 1) = 1 then fmul (acc, b) else acc
          in loop (fmul (b, b), IntInf.~>> (e, 0w1), acc) end
    in
      loop (base mod p, e, 1 : IntInf.int)
    end

  fun finv a = fpow (a, p - 2)

  (* decodeUCoordinate: mask the high (255th) bit of the last byte (RFC 7748). *)
  fun decodeUCoordinate s =
    let
      val () = require32 s
      fun byte i =
        if i = 31
        then Char.chr (Word.toInt (Word.andb (Word.fromInt (Char.ord (String.sub (s, 31))), 0wx7F)))
        else String.sub (s, i)
      val masked = CharVector.tabulate (keySize, byte)
    in
      leDecode masked mod p
    end

  (* a24 = (486662 - 2) / 4 *)
  val a24 : IntInf.int = 121665

  (* Conditional swap used by the Montgomery ladder.
   * [swap] is 0 or 1 and is derived from the (publicly ordered) bit index of
   * the scalar, so the branch here is on the loop structure rather than on
   * which field value is larger; this preserves the standard ladder shape. *)
  fun cswap (swap, a, b) = if swap = (1 : IntInf.int) then (b, a) else (a, b)

  (* X25519 scalar multiplication (RFC 7748 Montgomery ladder). *)
  fun scalarMult (scalarStr, uStr) =
    let
      val () = require32 scalarStr
      val () = require32 uStr
      val k = leDecode (clamp scalarStr)   (* clamp then decode as integer *)
      val x1 = decodeUCoordinate uStr
      (* ladder state *)
      fun loop (t, x2, z2, x3, z3, swapPrev) =
        if t < 0 then (x2, z2, swapPrev, x3, z3)
        else
          let
            val kt = IntInf.andb (IntInf.~>> (k, Word.fromInt t), 1)
            val swap = IntInf.xorb (swapPrev, kt)
            val (x2, x3) = cswap (swap, x2, x3)
            val (z2, z3) = cswap (swap, z2, z3)
            val swapPrev = kt

            val a = fadd (x2, z2)
            val aa = fmul (a, a)
            val b = fsub (x2, z2)
            val bb = fmul (b, b)
            val e = fsub (aa, bb)
            val c = fadd (x3, z3)
            val d = fsub (x3, z3)
            val da = fmul (d, a)
            val cb = fmul (c, b)
            val x3' = let val t = fadd (da, cb) in fmul (t, t) end
            val z3' = let val t = fsub (da, cb) in fmul (x1, fmul (t, t)) end
            val x2' = fmul (aa, bb)
            val z2' = fmul (e, fadd (aa, fmul (a24, e)))
          in
            loop (t - 1, x2', z2', x3', z3', swapPrev)
          end
      val (x2, z2, swapFinal, x3, z3) = loop (254, 1, 0, x1, 1, 0)
      (* final conditional swap *)
      val (x2, _) = cswap (swapFinal, x2, x3)
      val (z2, _) = cswap (swapFinal, z2, z3)
      val result = fmul (x2, finv z2)
    in
      leEncode result
    end

  fun dh scalarStr uStr = scalarMult (scalarStr, uStr)

  val basePoint =
    String.str (Char.chr 9) ^ CharVector.tabulate (31, fn _ => Char.chr 0)

  fun base scalarStr = scalarMult (scalarStr, basePoint)

  (* ----- hex convenience ----- *)

  val hexChars = "0123456789abcdef"

  fun toHex s =
    String.concat
      (List.map
         (fn c =>
            let val v = Char.ord c
            in String.str (String.sub (hexChars, v div 16)) ^
               String.str (String.sub (hexChars, v mod 16))
            end)
         (String.explode s))

  fun hexVal c =
    if c >= #"0" andalso c <= #"9" then SOME (Char.ord c - Char.ord #"0")
    else if c >= #"a" andalso c <= #"f" then SOME (Char.ord c - Char.ord #"a" + 10)
    else if c >= #"A" andalso c <= #"F" then SOME (Char.ord c - Char.ord #"A" + 10)
    else NONE

  fun fromHex s =
    let
      val n = String.size s
    in
      if n mod 2 <> 0 then NONE
      else
        let
          fun loop (i, acc) =
            if i >= n then SOME (String.implode (List.rev acc))
            else
              case (hexVal (String.sub (s, i)), hexVal (String.sub (s, i + 1))) of
                  (SOME hi, SOME lo) => loop (i + 2, Char.chr (hi * 16 + lo) :: acc)
                | _ => NONE
        in
          loop (0, [])
        end
    end

end
