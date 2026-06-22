(* p256.sml

   NIST P-256 / secp256r1 ECDH + ECDSA verify in pure Standard ML.

   Track A4 (Phase 3b).  Built on the vendored:
     - sml-bigint  : arbitrary-precision integers (field/scalar arithmetic)
     - sml-asn1    : DER SEQUENCE { INTEGER r, INTEGER s } for ECDSA
     - sml-codec   : SHA-256 for ECDSA message hashing

   Domain parameters (SEC2 / FIPS 186-4):
     p  = 2^256 - 2^224 + 2^192 + 2^96 - 1
     a  = -3 mod p
     b  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
     Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
     Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
     n  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

   Implementation notes:
     - Field arithmetic is built on the vendored sml-bigint (modular
       add/sub/mul via floored divMod; modular inverse via Fermat's
       little theorem, x^(p-2) mod p, since p is prime).
     - Scalar multiplication uses Jacobian projective coordinates so
       that point doubling and addition require NO modular inversion;
       exactly one inversion is performed at the end to recover the
       affine result.  This makes each scalar mult ~256 doublings +
       additions plus a single modpow, instead of ~256 modpows.
     - The double-and-add loop is left-to-right over the scalar bits.
       It is NOT constant-time: it is here for functional correctness
       against published test vectors, not for use with secret keys on
       a side-channel-observable machine.  The broader sml-tls
       hardening plan documents this boundary in Phase 8. *)

structure P256 :> P256 =
struct

  structure B = BigInt

  (* ===== P-256 domain parameters ===== *)

  (* Parse a known-good decimal constant (aborts if malformed, since
     these are compile-time literals that should never fail). *)
  fun lit s = case B.fromString s of SOME v => v | NONE => raise Fail ("bad literal: " ^ s)

  val p  = lit
    "115792089210356248762697446949407573530086143415290314195533631308867097853951"
  val a  = B.sub (p, B.fromInt 3)             (* -3 mod p *)
  val b  = lit
    "41058363725152142129326129780047268409114441015993725554835256314039467401291"
  val Gx = lit
    "48439561293906451759052585252797914202762949526041747995844080717082404635286"
  val Gy = lit
    "36134250956749795798585127919587881956611106672985015071877198253568414405109"
  val n  = lit
    "115792089210356248762697446949407573529996955224135760342422259061068512044369"

  val zero = B.fromInt 0
  val one  = B.fromInt 1
  val two  = B.fromInt 2
  val three = B.fromInt 3
  val eight = B.fromInt 8

  (* ===== Modular arithmetic in Fp ===== *)

  (* Reduce x mod m into the canonical non-negative residue.  Requires
     m > 0; x may be any sign.  Uses BigInt's floored divMod. *)
  fun mod_ (x, m) =
    let val (_, r) = B.divMod (x, m)
    in if B.compare (r, zero) = LESS then B.add (r, m) else r end

  (* Field operations mod p (the curve prime).  These are the hot path. *)
  fun fadd (x, y) = mod_ (B.add (x, y), p)
  fun fsub (x, y) = mod_ (B.sub (x, y), p)
  fun fmul (x, y) = mod_ (B.mul (x, y), p)
  fun fsqr x = fmul (x, x)

  (* Modular inverse via Fermat's little theorem: x^(p-2) mod p, since
     p is prime.  Used only ONCE per scalarMult (to convert the final
     Jacobian point back to affine) and a handful of times in ECDSA
     scalar-field work. *)
  fun invMod (x, m) =
    let val x' = mod_ (x, m)
    in
      if B.compare (x', zero) = EQUAL then raise Fail "invMod: zero divisor"
      else B.modpow (x', B.sub (m, two), m)
    end

  fun finv x = invMod (x, p)

  (* ===== Point representation =====
     The public `point` type is the affine pair {x, y} with x, y in
     [0, p).  Internally, scalar multiplication works in Jacobian
     projective coordinates (X, Y, Z) where the affine point is
     (X/Z^2, Y/Z^3); the point at infinity is Z == 0. *)

  type point = {x : B.int, y : B.int}

  (* Jacobian point: SOME (X, Y, Z) with Z <> 0 represents the affine
     point (X/Z^2, Y/Z^3); NONE is the point at infinity. *)
  type jac = (B.int * B.int * B.int) option

  (* ===== Jacobian point operations (no inversions) ===== *)

  (* Doubling in Jacobian coordinates for a = -3 (P-256).  Formula from
     EFD / Bernstein 2001 (dbl-2001-b):
       delta = Z1^2
       gamma = Y1^2
       beta  = X1 * gamma
       alpha = 3*(X1-delta)*(X1+delta)
       X3 = alpha^2 - 8*beta
       Z3 = (Y1+Z1)^2 - gamma - delta
       Y3 = alpha*(4*beta - X3) - 8*gamma^2
     NONE (infinity) returns NONE. *)
  fun jacDouble NONE = NONE
    | jacDouble (SOME (X1, Y1, Z1)) =
        if B.compare (Y1, zero) = EQUAL then NONE
        else
          let
            val delta = fsqr Z1
            val gamma = fsqr Y1
            val beta = fmul (X1, gamma)
            val t1 = fsub (X1, delta)
            val t2 = fadd (X1, delta)
            val alpha = fmul (three, fmul (t1, t2))
            val eightBeta = fmul (eight, beta)
            val X3 = fsub (fsqr alpha, eightBeta)
            val Y1Z1 = fadd (Y1, Z1)
            val Z3 = fsub (fsub (fsqr Y1Z1, gamma), delta)
            val fourBeta = fadd (beta, fadd (beta, fadd (beta, beta)))
            val Y3 = fsub (fmul (alpha, fsub (fourBeta, X3)),
                           fmul (eight, fsqr gamma))
          in
            SOME (X3, Y3, Z3)
          end

  (* Mixed addition: Jacobian P + affine Q (Q.z implicitly 1).  Formula
     from EFD (add-2007-bl, with Z2=1).  If P is NONE, returns Q in
     Jacobian (Z=1).  Returns NONE if P = -Q.  If P == Q, delegates to
     jacDouble. *)
  fun jacAddAffine (NONE, (Qx, Qy)) = SOME (Qx, Qy, one)
    | jacAddAffine (SOME (X1, Y1, Z1), (Qx, Qy)) =
        let
          val Z1Z1 = fsqr Z1
          val U2 = fmul (Qx, Z1Z1)
          val S2 = fmul (Qy, fmul (Z1, Z1Z1))
          val H = fsub (U2, X1)
          val HH = fsqr H
          val I = fadd (HH, fadd (HH, fadd (HH, HH)))   (* 4*HH *)
          val J = fmul (H, I)
          val r2 = fsub (S2, Y1)
          val r2' = fadd (r2, r2)                        (* 2*(S2-Y1) *)
          val V = fmul (X1, I)
          val twoV = fadd (V, V)
          val X3 = fsub (fsub (fsqr r2', J), twoV)      (* r^2 - J - 2*V *)
          val Y3 = fsub (fmul (r2', fsub (V, X3)),
                         fadd (fmul (Y1, J), fmul (Y1, J)))  (* r*(V-X3) - 2*Y1*J *)
          val Z3 = fsub (fsub (fsqr (fadd (Z1, H)), Z1Z1), HH)  (* (Z1+H)^2 - Z1Z1 - HH *)
        in
          if B.compare (H, zero) = EQUAL then
            (* P.x == Q.x.  If r2 == 0: P == Q (double); else P = -Q. *)
            if B.compare (r2, zero) = EQUAL
            then jacDouble (SOME (X1, Y1, Z1))
            else NONE
          else SOME (X3, Y3, Z3)
        end

  (* Convert a Jacobian point to affine; NONE stays NONE.  Performs the
     single modular inversion. *)
  fun jacToAffine NONE = NONE
    | jacToAffine (SOME (X, Y, Z)) =
        if B.compare (Z, zero) = EQUAL then NONE
        else
          let
            val Zinv = finv Z
            val Zinv2 = fsqr Zinv
            val Zinv3 = fmul (Zinv2, Zinv)
            val x = fmul (X, Zinv2)
            val y = fmul (Y, Zinv3)
          in
            SOME {x = x, y = y}
          end

  (* ===== Scalar multiplication ===== *)

  (* k * P where P is affine, returning an affine point option (NONE
     for the point at infinity).  Left-to-right double-and-add over the
     scalar bits, in Jacobian coordinates.  NOT constant-time. *)
  fun scalarMult (k, ptAff : point) =
    let
      val k' = mod_ (k, n)   (* reduce to [0, n) for safety *)
      val nbits = B.bitLength k'
      val Q = (#x ptAff, #y ptAff)
      fun loop i acc =
        if i < 0 then acc
        else
          let
            val acc' = jacDouble acc
            val acc'' =
              if B.testBit (k', i)
              then jacAddAffine (acc', Q)
              else acc'
          in
            loop (i - 1) acc''
          end
    in
      if B.compare (k', zero) = EQUAL then NONE
      else jacToAffine (loop (nbits - 1) NONE)
    end

  (* ===== Curve membership =====

     isOnCurve({x,y}):  y^2 == x^3 + a x + b (mod p),  and the point is
     not the point at infinity. *)
  fun isAffineOnCurve {x, y} =
    let
      val lhs = fsqr y
      val rhs = fadd (fmul (x, fsqr x), fadd (fmul (a, x), b))
    in
      B.compare (lhs, rhs) = EQUAL
    end

  (* ===== Byte encoding helpers ===== *)

  (* Encode a non-negative BigInt as a fixed-width big-endian byte
     string of `width` bytes, left-padded with zeros.  Raises Fail if
     the value does not fit. *)
  fun toBytesFixed (value, width) =
    let
      val v = if B.compare (value, zero) = LESS then raise Fail "toBytesFixed: negative"
              else value
      val raw = B.toBytes v                (* minimal big-endian, no leading zeros *)
      val rawLen = Word8Vector.length raw
    in
      if rawLen > width then raise Fail "toBytesFixed: value too large"
      else
        let
          val pad = String.implode (List.tabulate (width - rawLen, fn _ => #"\000"))
          val bodyChars =
            Word8Vector.foldr (fn (w, acc) => Char.chr (Word8.toInt w) :: acc) [] raw
          val body = String.implode bodyChars
        in
          pad ^ body
        end
    end

  (* Decode a big-endian unsigned byte string (raw SML string) into a
     BigInt.  Empty -> 0. *)
  fun fromBytes s =
    B.fromBytes
      (Word8Vector.fromList
         (List.map (Word8.fromInt o Char.ord) (String.explode s)))

  (* Decode a 32-byte big-endian unsigned scalar; returns NONE on
     malformed input (wrong length, zero, or >= n). *)
  fun decodeScalar s =
    if String.size s <> 32 then NONE
    else
      let val k = fromBytes s
      in if B.compare (k, zero) = EQUAL
         orelse B.compare (k, n) = GREATER
         orelse B.compare (k, n) = EQUAL
         then NONE else SOME k end

  (* Decode an uncompressed SEC1 public key (0x04 || X || Y, 65 bytes)
     into an affine point; returns NONE on any malformed input.  Does
     NOT check curve membership - that is isAffineOnCurve's job. *)
  fun decodePoint s =
    if String.size s <> 65 then NONE
    else if Char.ord (String.sub (s, 0)) <> 0x04 then NONE
    else
      let
        val xs = String.substring (s, 1, 32)
        val ys = String.substring (s, 33, 32)
        val x = fromBytes xs
        val y = fromBytes ys
      in
        if B.compare (x, p) = GREATER orelse B.compare (x, p) = EQUAL
           orelse B.compare (y, p) = GREATER orelse B.compare (y, p) = EQUAL
        then NONE
        else SOME {x = x, y = y}
      end

  (* Encode an affine point as the 65-byte uncompressed SEC1 form. *)
  fun encodePoint {x, y} =
    String.str (Char.chr 0x04) ^ toBytesFixed (x, 32) ^ toBytesFixed (y, 32)

  (* ===== Public API ===== *)

  (* Public key derivation: priv (32-byte scalar d in [1, n-1]) -> pub
     (65-byte uncompressed point d*G).  Total on well-formed input;
     raises Fail on a malformed private key (programming error). *)
  fun generatePublic (priv : string) : string =
    case decodeScalar priv of
      NONE => raise Fail "P256.generatePublic: bad private key"
    | SOME d =>
        case scalarMult (d, {x = Gx, y = Gy}) of
          NONE => raise Fail "P256.generatePublic: scalarMult returned infinity"
        | SOME pt => encodePoint pt

  (* Curve-membership check on an uncompressed public key.  Rejects the
     identity, off-curve points, and any malformed encoding. *)
  fun isOnCurve (pub : string) : bool =
    case decodePoint pub of
      NONE => false
    | SOME pt => isAffineOnCurve pt

  (* ECDH shared-secret derivation.  Returns the X-coordinate of the
     shared point (32 bytes), or NONE on a bad peer public key
     (off-curve / identity / malformed). *)
  fun ecdh {privateKey, peerPublic} : string option =
    case decodeScalar privateKey of
      NONE => NONE                       (* bad private key *)
    | SOME d =>
        case decodePoint peerPublic of
          NONE => NONE
        | SOME pt =>
            if not (isAffineOnCurve pt) then NONE
            else
              (case scalarMult (d, pt) of
                 NONE => NONE            (* peer pub was identity (cannot happen
                                           since decodePoint rejects 0x04-only) *)
               | SOME {x, ...} => SOME (toBytesFixed (x, 32)))

  (* ECDSA verify over the SHA-256 of `message`, per FIPS 186-4 §6.4.2.
     `signatureDer` is the DER SEQUENCE { INTEGER r, INTEGER s }.
     Returns false on a bad signature, a bad public key, or a malformed
     DER encoding (total - never raises on attacker-controlled input). *)
  fun ecdsaVerify {publicKey, message, signatureDer} : bool =
    let
      (* 1. Decode and validate the public key. *)
      val pubPt =
        case decodePoint publicKey of
          NONE => NONE
        | SOME pt => if isAffineOnCurve pt then SOME pt else NONE
      (* 2. Parse the DER signature into (r, s). *)
      val rsOpt =
        case Asn1.decodeOpt signatureDer of
          NONE => NONE
        | SOME (Asn1.Seq [Asn1.Int r, Asn1.Int s]) =>
            if B.compare (r, one) = LESS
               orelse B.compare (r, n) = GREATER orelse B.compare (r, n) = EQUAL
               orelse B.compare (s, one) = LESS
               orelse B.compare (s, n) = GREATER orelse B.compare (s, n) = EQUAL
            then NONE
            else SOME (r, s)
        | SOME _ => NONE
    in
      case (pubPt, rsOpt) of
        (SOME {x = Qx, y = Qy}, SOME (r, s)) =>
          let
            (* 3. Hash the message and reduce mod n to get e. *)
            val h = Sha256.digest message              (* 32 bytes *)
            val e = mod_ (fromBytes h, n)
            (* 4. w = s^-1 mod n. *)
            val w = invMod (s, n)
            (* 5. u1 = e*w mod n;  u2 = r*w mod n.  (Scalar-field
                  operations mod n, not mod p.) *)
            val u1n = mod_ (B.mul (e, w), n)
            val u2n = mod_ (B.mul (r, w), n)
            (* 6. (x1, y1) = u1*G + u2*Q;  reject infinity. *)
            val pG = scalarMult (u1n, {x = Gx, y = Gy})
            val pQ = scalarMult (u2n, {x = Qx, y = Qy})
            (* Point addition in affine for the final combine (just
               one add - the per-step cost is negligible). *)
            fun affineAdd (NONE, q) = q
              | affineAdd (p_pt, NONE) = p_pt
              | affineAdd (SOME {x = x1, y = y1}, SOME {x = x2, y = y2}) =
                  if B.compare (x1, x2) = EQUAL then
                    if B.compare (y1, y2) = EQUAL then
                      (* doubling *)
                      let
                        val sNum = fadd (fmul (three, fsqr x1), a)
                        val sDen = fmul (two, y1)
                        val s = fmul (sNum, finv sDen)
                        val x3 = fsub (fsqr s, fadd (x1, x1))
                        val y3 = fsub (fmul (s, fsub (x1, x3)), y1)
                      in SOME {x = x3, y = y3} end
                    else NONE  (* P + (-P) = O *)
                  else
                    let
                      val s = fmul (fsub (y2, y1), finv (fsub (x2, x1)))
                      val x3 = fsub (fsub (fsqr s, x1), x2)
                      val y3 = fsub (fmul (s, fsub (x1, x3)), y1)
                    in SOME {x = x3, y = y3} end
            val pt = affineAdd (pG, pQ)
          in
            case pt of
              NONE => false
            | SOME {x = x1, ...} =>
                (* 7. v = x1 mod n;  accept iff v == r. *)
                B.compare (mod_ (x1, n), r) = EQUAL
          end
      | _ => false
    end

end
