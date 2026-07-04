(* bigint.sml

   Sign-magnitude arbitrary-precision integers over base-2^32 limbs.

   A magnitude is a [Word32.word vector] in little-endian order (index 0 is
   least significant) carrying no high-order zero limbs; the empty vector is
   the magnitude of zero.  A number is that magnitude paired with a sign in
   {~1, 0, 1}; the sign is 0 exactly when the magnitude is empty.

   Limb products are accumulated in [Word64], which is wide enough that
   a*b + c + d never overflows for 32-bit a,b,c,d (the maximum is exactly
   2^64-1).  All multi-limb work is done before the abstract type [int] is
   introduced, so plain integer literals keep their ordinary [Int.int]
   meaning throughout the helpers. *)

structure BigInt :> BIGINT =
struct

  (* ===== limb-level helpers (operating on Word32.word vectors) ===== *)

  type limb = Word32.word
  type mag  = limb vector

  fun to64 (w : limb) : Word64.word = Word64.fromLarge (Word32.toLarge w)
  fun to32 (w : Word64.word) : limb = Word32.fromLarge (Word64.toLarge w)

  val base64 : Word64.word = 0wx100000000   (* 2^32 *)

  val empty : mag = Vector.fromList []

  fun magIsZero (m : mag) = Vector.length m = 0

  (* Drop trailing (high-order) zero limbs from an array, yielding a vector. *)
  fun normArr (a : limb array) : mag =
    let
      fun top i = if i < 0 then ~1
                  else if Array.sub (a, i) <> 0w0 then i
                  else top (i - 1)
      val hi = top (Array.length a - 1)
    in
      if hi < 0 then empty
      else Vector.tabulate (hi + 1, fn i => Array.sub (a, i))
    end

  fun normVec (v : mag) : mag =
    let
      fun top i = if i < 0 then ~1
                  else if Vector.sub (v, i) <> 0w0 then i
                  else top (i - 1)
      val hi = top (Vector.length v - 1)
    in
      if hi < 0 then empty
      else if hi + 1 = Vector.length v then v
      else Vector.tabulate (hi + 1, fn i => Vector.sub (v, i))
    end

  fun magCompare (a : mag, b : mag) : order =
    let
      val la = Vector.length a
      val lb = Vector.length b
    in
      if la <> lb then Int.compare (la, lb)
      else
        let
          fun loop i =
            if i < 0 then EQUAL
            else
              let val x = Vector.sub (a, i) and y = Vector.sub (b, i)
              in if x = y then loop (i - 1)
                 else if Word32.< (x, y) then LESS else GREATER
              end
        in loop (la - 1) end
    end

  fun magAdd (a : mag, b : mag) : mag =
    let
      val la = Vector.length a and lb = Vector.length b
      val n = Int.max (la, lb)
      fun la' i = if i < la then Vector.sub (a, i) else 0w0
      fun lb' i = if i < lb then Vector.sub (b, i) else 0w0
      val res = Array.array (n + 1, 0w0 : limb)
      fun loop (i, carry) =
        if i >= n then Array.update (res, n, to32 carry)
        else
          let val sum = Word64.+ (Word64.+ (to64 (la' i), to64 (lb' i)), carry)
          in
            Array.update (res, i, to32 sum);
            loop (i + 1, Word64.>> (sum, 0w32))
          end
    in
      loop (0, 0w0); normArr res
    end

  (* Precondition: a >= b (as magnitudes). *)
  fun magSub (a : mag, b : mag) : mag =
    let
      val la = Vector.length a and lb = Vector.length b
      fun lb' i = if i < lb then Vector.sub (b, i) else 0w0
      val res = Array.array (la, 0w0 : limb)
      fun loop (i, borrow) =
        if i >= la then ()
        else
          let
            val ai = to64 (Vector.sub (a, i))
            val bi = Word64.+ (to64 (lb' i), borrow)
          in
            if Word64.>= (ai, bi)
            then (Array.update (res, i, to32 (Word64.- (ai, bi))); loop (i + 1, 0w0))
            else (Array.update (res, i, to32 (Word64.- (Word64.+ (ai, base64), bi)));
                  loop (i + 1, 0w1))
          end
    in
      loop (0, 0w0); normArr res
    end

  fun magMulSchool (a : mag, b : mag) : mag =
    let
      val la = Vector.length a and lb = Vector.length b
    in
      if la = 0 orelse lb = 0 then empty
      else
        let
          val res = Array.array (la + lb, 0w0 : limb)
          fun outer i =
            if i >= la then ()
            else
              let
                val ai = to64 (Vector.sub (a, i))
                fun inner (j, carry) =
                  if j >= lb
                  then Array.update (res, i + lb, to32 carry)
                  else
                    let
                      val cur = to64 (Array.sub (res, i + j))
                      val prod = Word64.+ (Word64.+ (Word64.* (ai, to64 (Vector.sub (b, j))), cur), carry)
                    in
                      Array.update (res, i + j, to32 prod);
                      inner (j + 1, Word64.>> (prod, 0w32))
                    end
              in
                inner (0, 0w0); outer (i + 1)
              end
        in
          outer 0; normArr res
        end
    end

  (* Shift a magnitude left by [k] whole limbs (multiply by base^k). *)
  fun shiftLimbs (v : mag, k) : mag =
    if Vector.length v = 0 then empty
    else Vector.tabulate (Vector.length v + k,
            fn i => if i < k then 0w0 else Vector.sub (v, i - k))

  (* Low [m] limbs / the rest, as a (low, high) split. *)
  fun splitAt (v : mag, m) : mag * mag =
    let val n = Vector.length v
    in
      if m >= n then (v, empty)
      else (normVec (Vector.tabulate (m, fn i => Vector.sub (v, i))),
            normVec (Vector.tabulate (n - m, fn i => Vector.sub (v, i + m))))
    end

  val karatsubaCutoff = 32

  fun magMul (a : mag, b : mag) : mag =
    let
      val la = Vector.length a and lb = Vector.length b
    in
      if la = 0 orelse lb = 0 then empty
      else if la < karatsubaCutoff orelse lb < karatsubaCutoff
      then magMulSchool (a, b)
      else
        let
          val m = Int.div (Int.max (la, lb) + 1, 2)
          val (a0, a1) = splitAt (a, m)
          val (b0, b1) = splitAt (b, m)
          val z0 = magMul (a0, b0)
          val z2 = magMul (a1, b1)
          val z1 = magSub (magSub (magMul (magAdd (a0, a1), magAdd (b0, b1)), z2), z0)
        in
          magAdd (magAdd (shiftLimbs (z2, 2 * m), shiftLimbs (z1, m)), z0)
        end
    end

  (* ----- bit-level helpers for division, gcd and shifting ----- *)

  fun limbBitLength (w : limb) : int =
    let fun loop (w, n) = if w = 0w0 then n else loop (Word32.>> (w, 0w1), n + 1)
    in loop (w, 0) end

  fun bitLength (v : mag) : int =
    let val n = Vector.length v
    in if n = 0 then 0 else (n - 1) * 32 + limbBitLength (Vector.sub (v, n - 1)) end

  fun testBit (v : mag, i) : bool =
    let val li = Int.div (i, 32) and bi = Int.mod (i, 32)
    in
      li < Vector.length v
      andalso Word32.andb (Word32.>> (Vector.sub (v, li), Word.fromInt bi), 0w1) = 0w1
    end

  (* Multiply by two and OR in a low bit (used by binary long division). *)
  fun magShl1 (v : mag, lowbit) : mag =
    let
      val n = Vector.length v
      val res = Array.array (n + 1, 0w0 : limb)
      fun loop (i, carry) =
        if i >= n then Array.update (res, n, to32 carry)
        else
          let val x = Word64.+ (Word64.<< (to64 (Vector.sub (v, i)), 0w1), carry)
          in Array.update (res, i, to32 x); loop (i + 1, Word64.>> (x, 0w32)) end
    in
      loop (0, if lowbit then 0w1 else 0w0); normArr res
    end

  fun shrBits (v : mag, k) : mag =
    let
      val limbShift = Int.div (k, 32) and bitShift = Int.mod (k, 32)
      val n = Vector.length v
    in
      if limbShift >= n then empty
      else
        let
          val m = n - limbShift
          fun limb i = Vector.sub (v, i + limbShift)
        in
          if bitShift = 0 then normVec (Vector.tabulate (m, limb))
          else
            normVec (Vector.tabulate (m, fn i =>
              let
                val lo = Word32.>> (limb i, Word.fromInt bitShift)
                val hi = if i + 1 < m
                         then Word32.<< (limb (i + 1), Word.fromInt (32 - bitShift))
                         else 0w0
              in Word32.orb (lo, hi) end))
        end
    end

  fun shlBits (v : mag, k) : mag =
    if Vector.length v = 0 then empty
    else
      let
        val limbShift = Int.div (k, 32) and bitShift = Int.mod (k, 32)
        val n = Vector.length v
      in
        if bitShift = 0
        then normVec (Vector.tabulate (n + limbShift,
               fn i => if i < limbShift then 0w0 else Vector.sub (v, i - limbShift)))
        else
          normVec (Vector.tabulate (n + limbShift + 1, fn i =>
            if i < limbShift then 0w0
            else
              let
                val j = i - limbShift
                val lo = if j < n then Word32.<< (Vector.sub (v, j), Word.fromInt bitShift) else 0w0
                val hi = if j >= 1 andalso j - 1 < n
                         then Word32.>> (Vector.sub (v, j - 1), Word.fromInt (32 - bitShift))
                         else 0w0
              in Word32.orb (lo, hi) end))
      end

  fun trailingZeros (v : mag) : int =
    let
      val n = Vector.length v
      fun firstNonZero i = if i >= n then ~1
                           else if Vector.sub (v, i) <> 0w0 then i
                           else firstNonZero (i + 1)
      val fi = firstNonZero 0
    in
      if fi < 0 then 0
      else
        let
          val w = Vector.sub (v, fi)
          fun ctz (w, n) = if Word32.andb (w, 0w1) = 0w1 then n
                           else ctz (Word32.>> (w, 0w1), n + 1)
        in fi * 32 + ctz (w, 0) end
    end

  (* Binary long division of magnitudes; b must be non-zero.
     Returns (quotient, remainder). *)
  fun magDivMod (a : mag, b : mag) : mag * mag =
    if magIsZero a then (empty, empty)
    else
      case magCompare (a, b) of
          LESS => (empty, a)
        | EQUAL => (Vector.fromList [0w1], empty)
        | GREATER =>
            let
              val nbits = bitLength a
              val qbits = Array.array (nbits, false)
              fun loop (i, r) =
                if i < 0 then r
                else
                  let val r1 = magShl1 (r, testBit (a, i))
                  in
                    case magCompare (r1, b) of
                        LESS => loop (i - 1, r1)
                      | _ => (Array.update (qbits, i, true); loop (i - 1, magSub (r1, b)))
                  end
              val r = loop (nbits - 1, empty)
              val nlimbs = Int.div (nbits + 31, 32)
              val qa = Array.array (nlimbs, 0w0 : limb)
              fun pack i =
                if i >= nbits then ()
                else
                  ( if Array.sub (qbits, i)
                    then
                      let
                        val li = Int.div (i, 32) and bi = Int.mod (i, 32)
                      in
                        Array.update (qa, li,
                          Word32.orb (Array.sub (qa, li), Word32.<< (0w1, Word.fromInt bi)))
                      end
                    else ()
                  ; pack (i + 1) )
            in
              pack 0; (normArr qa, r)
            end

  (* Binary (Stein) GCD on non-zero magnitudes. *)
  fun magGcd (a : mag, b : mag) : mag =
    let
      val shift = Int.min (trailingZeros a, trailingZeros b)
      fun loop (u, v) =
        let
          val v = shrBits (v, trailingZeros v)
          val (u, v) = if magCompare (u, v) = GREATER then (v, u) else (u, v)
          val d = magSub (v, u)
        in
          if magIsZero d then u else loop (u, d)
        end
      val u0 = shrBits (a, trailingZeros a)
    in
      shlBits (loop (u0, b), shift)
    end

  (* ===== sign-magnitude layer ===== *)

  datatype bigint = BI of Int.int * mag   (* sign in {~1,0,1}, magnitude *)

  fun mk (sgn, m) = if magIsZero m then BI (0, empty) else BI (sgn, m)

  val zeroB = BI (0, empty)
  val oneB  = BI (1, Vector.fromList [0w1])

  (* ----- conversions ----- *)

  (* Conversions go through base-2^16 chunks, which fit the host [Int] on every
     platform (32-bit MLton as well as Poly/ML's 63-bit Int -- both fixed-width;
     only IntInf is arbitrary precision), while the limbs themselves remain
     base-2^32. *)

  fun fromInt n =
    if n = 0 then zeroB
    else
      let
        val sgn = if n < 0 then ~1 else 1
        (* base-2^16 chunks, most significant first (built by prepending) *)
        fun chunks (n, acc) =
          if n = 0 then acc
          else chunks (Int.quot (n, 65536),
                       Word32.fromInt (Int.abs (Int.rem (n, 65536))) :: acc)
        val hiToLo = chunks (n, [])
        val loToHi = List.rev hiToLo          (* little-endian base-2^16 digits *)
        (* pack pairs of 16-bit chunks into 32-bit limbs *)
        fun pack ([], acc) = List.rev acc
          | pack ([lo], acc) = List.rev (lo :: acc)
          | pack (lo :: hi :: rest, acc) =
              pack (rest, Word32.orb (lo, Word32.<< (hi, 0w16)) :: acc)
        val limbs = pack (loToHi, [])
      in
        mk (sgn, normVec (Vector.fromList limbs))
      end

  fun toInt (BI (sgn, mag)) =
    let
      fun horner (acc, w) =
        let
          val lo = Word32.toInt (Word32.andb (w, 0wxFFFF))
          val hi = Word32.toInt (Word32.>> (w, 0w16))
        in
          (acc * 65536 + sgn * hi) * 65536 + sgn * lo
        end
      fun loop (i, acc) =
        if i < 0 then acc else loop (i - 1, horner (acc, Vector.sub (mag, i)))
    in
      SOME (loop (Vector.length mag - 1, 0)) handle Overflow => NONE
    end

  (* ----- comparison / sign / abs ----- *)

  fun compare (BI (sa, ma), BI (sb, mb)) =
    if sa <> sb then Int.compare (sa, sb)
    else
      case sa of
          0 => EQUAL
        | 1 => magCompare (ma, mb)
        | _ => magCompare (mb, ma)

  fun sign (BI (s, _)) = fromInt s
  fun absB (BI (s, m)) = if s = 0 then zeroB else BI (1, m)
  fun negate (BI (s, m)) = BI (~s, m)

  (* ----- additive arithmetic ----- *)

  fun add (BI (sa, ma), BI (sb, mb)) =
    if sa = 0 then BI (sb, mb)
    else if sb = 0 then BI (sa, ma)
    else if sa = sb then mk (sa, magAdd (ma, mb))
    else
      case magCompare (ma, mb) of
          EQUAL => zeroB
        | GREATER => mk (sa, magSub (ma, mb))
        | LESS => mk (sb, magSub (mb, ma))

  fun sub (a, b) = add (a, negate b)

  fun mul (BI (sa, ma), BI (sb, mb)) =
    if sa = 0 orelse sb = 0 then zeroB
    else mk (sa * sb, magMul (ma, mb))

  (* ----- division ----- *)

  fun quotRem (BI (sa, ma), BI (sb, mb)) =
    if sb = 0 then raise Div
    else if sa = 0 then (zeroB, zeroB)
    else
      let
        val (q, r) = magDivMod (ma, mb)
      in
        (mk (sa * sb, q), mk (sa, r))
      end

  fun divMod (a as BI (sa, _), b as BI (sb, _)) =
    if sb = 0 then raise Div
    else
      let
        val (q, r) = quotRem (a, b)
      in
        case r of
            BI (0, _) => (q, r)
          | _ => if sa = sb then (q, r)
                 else (sub (q, oneB), add (r, b))
      end

  (* ----- string output ----- *)

  fun digitChar d =
    if d < 10 then Char.chr (Char.ord #"0" + d)
    else Char.chr (Char.ord #"a" + (d - 10))

  fun toStringRadix radix n =
    let
      val rI =
        case toInt radix of
            SOME r => r
          | NONE => raise Domain
      val () = if rI < 2 orelse rI > 36 then raise Domain else ()
      val BI (sgn, mag) = n
    in
      if sgn = 0 then "0"
      else
        let
          val rMag = (case radix of BI (_, m) => m)
          fun loop (m, acc) =
            if magIsZero m then acc
            else
              let
                val (q, r) = magDivMod (m, rMag)
                val d = case toInt (mk (1, r)) of SOME x => x | NONE => raise Domain
              in
                loop (q, digitChar d :: acc)
              end
          val digits = loop (mag, [])
          val body = String.implode digits
        in
          if sgn < 0 then "~" ^ body else body
        end
    end

  fun toString n = toStringRadix (fromInt 10) n

  (* ----- string input (base 10) ----- *)

  val tenB = fromInt 10

  fun fromString str =
    let
      val n = String.size str
    in
      if n = 0 then NONE
      else
        let
          val c0 = String.sub (str, 0)
          val (neg, start) =
            if c0 = #"~" orelse c0 = #"-" then (true, 1)
            else if c0 = #"+" then (false, 1)
            else (false, 0)
        in
          if start >= n then NONE
          else
            let
              fun loop (i, acc) =
                if i >= n then SOME acc
                else
                  let val c = String.sub (str, i)
                  in
                    if Char.isDigit c
                    then loop (i + 1, add (mul (acc, tenB), fromInt (Char.ord c - Char.ord #"0")))
                    else NONE
                  end
            in
              case loop (start, zeroB) of
                  NONE => NONE
                | SOME v => SOME (if neg then negate v else v)
            end
        end
    end

  (* ----- powers ----- *)

  fun pow (b, e) =
    let
      val BI (se, me) = e
    in
      if se < 0 then raise Domain
      else if se = 0 then oneB
      else
        let
          val nbits = bitLength me
          fun loop (i, acc) =
            if i < 0 then acc
            else
              let val acc2 = mul (acc, acc)
              in loop (i - 1, if testBit (me, i) then mul (acc2, b) else acc2) end
        in
          loop (nbits - 1, oneB)
        end
    end

  fun gcd (a, b) =
    let
      val BI (sa, ma) = absB a
      val BI (sb, mb) = absB b
    in
      if sa = 0 then absB b
      else if sb = 0 then absB a
      else BI (1, magGcd (ma, mb))
    end

  fun modpow (b, e, m) =
    let
      val BI (se, me) = e
    in
      if se < 0 then raise Domain
      else
        case compare (m, oneB) of
            LESS => raise Div                 (* m <= 0 *)
          | EQUAL => zeroB                     (* anything mod 1 = 0 *)
          | GREATER =>
              let
                fun reduce x = #2 (divMod (x, m))   (* floored: residue in [0, m) *)
                val base0 = reduce b
                val nbits = bitLength me
                fun loop (i, acc) =
                  if i < 0 then acc
                  else
                    let val acc2 = reduce (mul (acc, acc))
                    in loop (i - 1, if testBit (me, i) then reduce (mul (acc2, base0)) else acc2) end
              in
                if se = 0 then reduce oneB else loop (nbits - 1, oneB)
              end
    end

  (* ----- deterministic Miller-Rabin ----- *)

  val witnessBases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

  fun isProbablePrime (n, rounds) =
    let
      val twoB = fromInt 2
    in
      case compare (n, twoB) of
          LESS => false                        (* n < 2 *)
        | EQUAL => true                        (* n = 2 *)
        | GREATER =>
            let
              val BI (_, mn) = n
            in
              if not (testBit (mn, 0)) then false   (* even and > 2 *)
              else
                let
                  val nMinus1 = sub (n, oneB)
                  val BI (_, mnm1) = nMinus1
                  val sShift = trailingZeros mnm1
                  val d = BI (1, shrBits (mnm1, sShift))    (* n-1 = d * 2^sShift *)
                  val howMany =
                    case toInt rounds of
                        SOME r => Int.max (1, Int.min (r, List.length witnessBases))
                      | NONE => List.length witnessBases
                  val bases = List.take (witnessBases, howMany)
                  (* one Miller-Rabin trial; true => "probably prime" for this base *)
                  fun trial a0 =
                    let
                      val a = fromInt a0
                    in
                      if compare (a, nMinus1) <> LESS then true   (* skip a >= n-1 *)
                      else
                        let
                          val x0 = modpow (a, d, n)
                        in
                          if compare (x0, oneB) = EQUAL orelse compare (x0, nMinus1) = EQUAL
                          then true
                          else
                            let
                              fun sq (j, x) =
                                if j <= 0 then false
                                else
                                  let val x2 = #2 (divMod (mul (x, x), n))
                                  in
                                    if compare (x2, nMinus1) = EQUAL then true
                                    else if compare (x2, oneB) = EQUAL then false
                                    else sq (j - 1, x2)
                                  end
                            in sq (sShift - 1, x0) end
                        end
                    end
                  fun allTrials [] = true
                    | allTrials (a :: rest) = trial a andalso allTrials rest
                in
                  allTrials bases
                end
            end
    end

  (* ===== additive extensions ===== *)

  val twoB = fromInt 2
  val oneMag : mag = Vector.fromList [0w1]

  (* ----- bitwise operations (infinite two's complement) ----- *)

  fun magLimb (m : mag, i) : limb =
    if i < Vector.length m then Vector.sub (m, i) else 0w0

  (* (isNeg, i-th limb of the infinite two's complement of n).  For a negative
     value with magnitude m, the two's complement is ~(m - 1), so each limb is
     the bitwise complement of the corresponding limb of (m - 1); beyond the
     length of (m - 1) the complement yields all-ones, the correct sign fill. *)
  fun tcView (BI (s, m)) =
    if s >= 0 then (false, fn i => magLimb (m, i))
    else
      let val m1 = magSub (m, oneMag)
      in (true, fn i => Word32.notb (magLimb (m1, i))) end

  fun bitwise opf (a as BI (_, ma), b as BI (_, mb)) =
    let
      val (na, fa) = tcView a
      val (nb, fb) = tcView b
      val extA : limb = if na then 0wxFFFFFFFF else 0w0
      val extB : limb = if nb then 0wxFFFFFFFF else 0w0
      val resNeg = opf (extA, extB) = (0wxFFFFFFFF : limb)
      val n = Int.max (Vector.length ma, Vector.length mb) + 1
      val r = Array.tabulate (n, fn i => opf (fa i, fb i))
    in
      if not resNeg then mk (1, normArr r)
      else
        (* result is negative: recover its magnitude as ~r + 1 *)
        let
          val res = Array.array (n, 0w0 : limb)
          fun loop (i, carry) =
            if i >= n then ()
            else
              let val x = Word64.+ (to64 (Word32.notb (Array.sub (r, i))), carry)
              in Array.update (res, i, to32 x); loop (i + 1, Word64.>> (x, 0w32)) end
        in
          loop (0, 0w1); mk (~1, normArr res)
        end
    end

  fun andbB (a, b) = bitwise Word32.andb (a, b)
  fun orbB  (a, b) = bitwise Word32.orb  (a, b)
  fun xorbB (a, b) = bitwise Word32.xorb (a, b)
  fun notbB n = negate (add (n, oneB))            (* ~n - 1 *)

  fun shlB (n, k) =
    if k < 0 then raise Domain
    else let val BI (s, m) = n in mk (s, shlBits (m, k)) end

  (* Arithmetic (floored) right shift: `shr (n, k) = floor (n / 2^k)`, i.e.
     `IntInf.div (n, 2^k)`. This is the correct sign-extending shift and matches
     MLton's `IntInf.~>>`; note Poly/ML 5.9.2's `IntInf.~>>` is buggy for large
     negatives (it truncates toward zero), so this implementation is the
     portable, correct one. *)
  fun shrB (n, k) =
    if k < 0 then raise Domain
    else
      let val BI (s, m) = n
      in
        if s >= 0 then mk (s, shrBits (m, k))
        else
          let
            val q = shrBits (m, k)
            val exact = magCompare (shlBits (q, k), m) = EQUAL
          in
            if exact then mk (~1, q) else mk (~1, magAdd (q, oneMag))
          end
      end

  fun bitLengthOf (BI (_, m)) = bitLength m

  fun bitB (n, i) =
    if i < 0 then raise Domain
    else
      let
        val (_, lf) = tcView n
        val li = Int.div (i, 32) and bi = Int.mod (i, 32)
      in
        Word32.andb (Word32.>> (lf li, Word.fromInt bi), 0w1) = 0w1
      end

  fun setBitB (n, i) = orbB (n, shlB (oneB, i))
  fun clearBitB (n, i) = if bitB (n, i) then xorbB (n, shlB (oneB, i)) else n

  fun popcountB n =
    let
      val BI (_, m) = absB n
      fun limbPop (w, acc) =
        if w = 0w0 then acc
        else limbPop (Word32.>> (w, 0w1),
                      acc + (if Word32.andb (w, 0w1) = 0w1 then 1 else 0))
      fun loop (i, acc) =
        if i >= Vector.length m then acc
        else loop (i + 1, limbPop (Vector.sub (m, i), acc))
    in loop (0, 0) end

  (* ----- integer roots ----- *)

  fun isqrtB n =
    case compare (n, zeroB) of
        LESS => raise Domain
      | EQUAL => zeroB
      | GREATER =>
          let
            val bl = bitLengthOf n
            val x0 = shlB (oneB, Int.div (bl + 1, 2))    (* x0 >= floor(sqrt n) *)
            fun loop x =
              let val y = #1 (divMod (add (x, #1 (divMod (n, x))), twoB))
              in if compare (y, x) = LESS then loop y else x end
          in loop x0 end

  fun nthRootB (k, n) =
    if k < 1 then raise Domain
    else if compare (n, zeroB) = LESS then raise Domain
    else if k = 1 then n
    else if compare (n, zeroB) = EQUAL then zeroB
    else if k = 2 then isqrtB n
    else
      let
        val kB = fromInt k
        val km1 = fromInt (k - 1)
        val bl = bitLengthOf n
        val x0 = shlB (oneB, Int.div (bl + k - 1, k) + 1)    (* upper bound *)
        fun newton x =
          let
            val xk1 = pow (x, km1)
            val y = #1 (divMod (add (mul (km1, x), #1 (divMod (n, xk1))), kB))
          in if compare (y, x) = LESS then newton y else x end
        val approx = newton x0
        (* tighten to the exact floor with bounded correction steps *)
        fun down x = if compare (pow (x, kB), n) = GREATER then down (sub (x, oneB)) else x
        val x1 = down approx
        fun up x = if compare (pow (add (x, oneB), kB), n) <> GREATER then up (add (x, oneB)) else x
      in up x1 end

  (* ----- byte serialization (big-endian, unsigned magnitude) ----- *)

  fun toBytesB n =
    let
      val BI (_, m) = absB n
      val nbits = bitLength m
    in
      if nbits = 0 then Word8Vector.fromList []
      else
        let
          val nbytes = Int.div (nbits + 7, 8)
          fun byteAt j =
            let
              val idx = nbytes - 1 - j               (* little-endian byte index *)
              val limbIdx = Int.div (idx, 4)
              val shift = Int.mod (idx, 4) * 8
              val w = magLimb (m, limbIdx)
              val b = Word32.andb (Word32.>> (w, Word.fromInt shift), 0wxFF)
            in Word8.fromLarge (Word32.toLarge b) end
        in
          Word8Vector.tabulate (nbytes, byteAt)
        end
    end

  fun fromBytesB v =
    let
      val n = Word8Vector.length v
      fun loop (i, acc) =
        if i >= n then acc
        else loop (i + 1, add (shlB (acc, 8), fromInt (Word8.toInt (Word8Vector.sub (v, i)))))
    in loop (0, zeroB) end

  (* ----- public names ----- *)

  type int = bigint
  val op~ = negate
  val op+ = add
  val op- = sub
  val op* = mul
  val abs = absB

  val isqrt = isqrtB
  val sqrt = isqrtB
  val nthRoot = nthRootB
  val andb = andbB
  val orb = orbB
  val xorb = xorbB
  val notb = notbB
  val shl = shlB
  val shr = shrB
  val bit = bitB
  val testBit = bitB
  val setBit = setBitB
  val clearBit = clearBitB
  val popcount = popcountB
  val bitLength = bitLengthOf
  val toBytes = toBytesB
  val fromBytes = fromBytesB
end
