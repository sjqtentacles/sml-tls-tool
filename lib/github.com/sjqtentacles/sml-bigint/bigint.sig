(* bigint.sig

   Arbitrary-precision signed integers in pure Standard ML.

   The representation is sign-magnitude over a base-2^32 limb vector
   (little-endian).  Multiplication uses Karatsuba above a small cutoff and
   schoolbook below it; division is binary long division; GCD is the binary
   (Stein) algorithm; modular exponentiation is square-and-multiply; and
   primality testing is deterministic Miller-Rabin over fixed witness bases.

   The abstract type is named [int] so the structure reads like an integer
   module.  Parameters whose natural type is the host machine integer are
   given as [Int.int]; every other [int] in this signature is the
   arbitrary-precision type.  String output follows the Basis convention of a
   leading "~" for negatives, so [toString] agrees character-for-character
   with [IntInf.toString]. *)

signature BIGINT =
sig
  type int

  (* ---- Conversions ---- *)

  (* Inject a host integer (handles the most-negative value). *)
  val fromInt   : Int.int -> int
  (* Project to a host integer; NONE when out of [Int] range. *)
  val toInt     : int -> Int.int option
  (* Parse a base-10 numeral with an optional leading "~", "-" or "+".
     NONE on empty input or any non-digit. *)
  val fromString : string -> int option
  (* Base-10 numeral, "~"-prefixed when negative. *)
  val toString  : int -> string
  (* [toStringRadix r n] renders n in radix r (2 <= r <= 36) using digits
     0-9a-z, "~"-prefixed when negative.  The radix is itself an [int]. *)
  val toStringRadix : int -> int -> string

  (* ---- Arithmetic ---- *)

  val ~   : int -> int
  val +   : int * int -> int
  val -   : int * int -> int
  val *   : int * int -> int
  (* Prefix spellings of the operators above, for ergonomic qualified use. *)
  val add : int * int -> int
  val sub : int * int -> int
  val mul : int * int -> int

  (* Floored division: the remainder takes the sign of the divisor.
     Agrees with [IntInf.divMod].  Raises [Div] when the divisor is zero. *)
  val divMod  : int * int -> int * int
  (* Truncated division: the remainder takes the sign of the dividend.
     Agrees with [IntInf.quotRem].  Raises [Div] when the divisor is zero. *)
  val quotRem : int * int -> int * int

  val compare : int * int -> order
  (* The sign as a bignum: ~1, 0 or 1. *)
  val sign : int -> int
  val abs  : int -> int

  (* [pow (b, e)] is b raised to e; raises [Domain] for negative e. *)
  val pow  : int * int -> int
  (* Greatest common divisor, always non-negative. *)
  val gcd  : int * int -> int
  (* [modpow (b, e, m)] is (b^e) mod m for e >= 0 and m > 0; the result is the
     non-negative residue.  Raises [Domain] for negative e, [Div] for m <= 0. *)
  val modpow : int * int * int -> int
  (* Deterministic Miller-Rabin.  The second argument is the number of fixed
     small witness bases to try (clamped to the table size). *)
  val isProbablePrime : int * int -> bool

  (* ---- Integer roots ---- *)

  (* [isqrt n] is the floor of the square root of n; raises [Domain] for n < 0.
     Satisfies isqrt n * isqrt n <= n < (isqrt n + 1) * (isqrt n + 1). *)
  val isqrt : int -> int
  (* An alias for [isqrt]. *)
  val sqrt  : int -> int
  (* [nthRoot (k, n)] is the floor of the k-th root of n, for k >= 1 and n >= 0.
     Raises [Domain] when k < 1 or n < 0. *)
  val nthRoot : Int.int * int -> int

  (* ---- Bitwise operations ----

     [andb], [orb], [xorb] and [notb] treat each operand as an infinite
     two's-complement bit string (negatives have infinite leading ones), so the
     results agree with [IntInf.andb]/[orb]/[xorb]/[notb] for every sign.  The
     shifts are arithmetic: [shl (n, k)] multiplies by 2^k and [shr (n, k)] is a
     floored divide by 2^k, agreeing with [IntInf.<<] and [IntInf.~>>].  Bit
     indices are 0-based from the least-significant bit; negative shift or bit
     indices raise [Domain]. *)
  val andb : int * int -> int
  val orb  : int * int -> int
  val xorb : int * int -> int
  val notb : int -> int
  val shl  : int * Int.int -> int
  val shr  : int * Int.int -> int
  (* [bit (n, i)] / [testBit (n, i)] is the i-th two's-complement bit of n. *)
  val bit     : int * Int.int -> bool
  val testBit : int * Int.int -> bool
  (* [n] with two's-complement bit i set / cleared. *)
  val setBit   : int * Int.int -> int
  val clearBit : int * Int.int -> int
  (* The number of set bits in the magnitude |n|. *)
  val popcount  : int -> Int.int
  (* The number of bits in the magnitude |n|; [bitLength] of 0 is 0. *)
  val bitLength : int -> Int.int

  (* ---- Byte serialization (big-endian, unsigned magnitude) ----

     [toBytes n] is the minimal big-endian byte string of the magnitude |n|
     (no leading zero bytes; 0 encodes as the empty vector); the sign is
     dropped.  [fromBytes] reads a big-endian unsigned magnitude and always
     yields a value >= 0.  Hence [fromBytes (toBytes n) = n] for all n >= 0,
     e.g. 256 <-> [0wx01, 0wx00] and 0 <-> []. *)
  val toBytes   : int -> Word8Vector.vector
  val fromBytes : Word8Vector.vector -> int
end
