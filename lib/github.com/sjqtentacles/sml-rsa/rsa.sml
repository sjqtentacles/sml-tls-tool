(* rsa.sml

   RSA per RFC 8017 (PKCS#1 v2.2) in pure Standard ML.

   Integers are the vendored arbitrary-precision [BigInt]; bytes are raw
   [string]s (one [char] = one octet, 0..255).  The number-theoretic core is
   RSAEP/RSADP (modular exponentiation, with the private operation taking the
   Chinese-Remainder path), and the padding layers (EMSA-PKCS1-v1_5, EME-OAEP,
   EMSA-PSS, EME-PKCS1-v1_5) sit on top of I2OSP / OS2IP and an MGF1 mask
   generator.  DigestInfo and the PKCS#1 / SPKI / PKCS#8 key structures are
   built with the vendored [Asn1] DER codec, and key text framing with [Pem].
   The hashes come from the vendored [Sha1] / [Sha256] / [Sha512]. *)

structure Rsa :> RSA =
struct
  structure B = BigInt

  type pubkey  = { n : B.int, e : B.int }
  type privkey = { n : B.int, e : B.int, d : B.int
                 , p : B.int, q : B.int
                 , dp : B.int, dq : B.int, qinv : B.int }
  type keypair = { pub : pubkey, priv : privkey }

  exception RSA of string

  datatype hash = SHA1 | SHA256 | SHA512

  (* ---------------------------------------------------------------- *)
  (* small numeric / byte helpers                                     *)
  (* ---------------------------------------------------------------- *)

  val zero = B.fromInt 0
  val one  = B.fromInt 1
  val two  = B.fromInt 2
  val b256 = B.fromInt 256

  fun byte n = String.str (Char.chr n)
  fun ordOf (s, i) = Char.ord (String.sub (s, i))
  fun zeros n = String.implode (List.tabulate (n, fn _ => Char.chr 0))
  fun pow2 k = B.pow (two, B.fromInt k)

  fun isEven x = B.compare (#2 (B.divMod (x, two)), zero) = EQUAL

  (* non-negative remainder x mod m (m > 0) *)
  fun modNN (x, m) = #2 (B.divMod (x, m))

  (* ---- hex ---- *)
  val hexChars = "0123456789abcdef"
  fun toHex s =
    String.concat
      (List.map (fn c =>
         let val n = Char.ord c
         in String.implode [String.sub (hexChars, n div 16), String.sub (hexChars, n mod 16)] end)
       (String.explode s))

  fun fromHex s =
    let
      fun hv c =
        if c >= #"0" andalso c <= #"9" then Char.ord c - 48
        else if c >= #"a" andalso c <= #"f" then Char.ord c - 87
        else if c >= #"A" andalso c <= #"F" then Char.ord c - 55
        else raise RSA "fromHex: bad digit"
      val cs = List.filter (fn c => not (Char.isSpace c)) (String.explode s)
      fun loop (a :: b :: rest) = Char.chr (hv a * 16 + hv b) :: loop rest
        | loop [] = []
        | loop [_] = raise RSA "fromHex: odd length"
    in String.implode (loop cs) end

  (* ---- I2OSP / OS2IP ---- *)

  (* big-endian unsigned bytes of x >= 0, exactly [len] octets *)
  fun i2osp (x, len) =
    if B.compare (x, zero) = LESS then raise RSA "I2OSP: negative integer"
    else
      let
        fun digits (x, acc) =
          if B.compare (x, zero) = EQUAL then acc
          else let val (q, r) = B.divMod (x, b256)
               in digits (q, valOf (B.toInt r) :: acc) end
        val ds = digits (x, [])
        val l  = List.length ds
      in
        if l > len then raise RSA "I2OSP: integer too large for the requested length"
        else zeros (len - l) ^ String.implode (List.map Char.chr ds)
      end

  fun os2ip s =
    let
      val n = String.size s
      fun loop (i, acc) =
        if i = n then acc
        else loop (i + 1, B.add (B.mul (acc, b256), B.fromInt (ordOf (s, i))))
    in loop (0, zero) end

  (* bit length of n >= 0 *)
  fun bitLength n =
    let fun loop (x, acc) =
          if B.compare (x, zero) = EQUAL then acc
          else loop (#1 (B.divMod (x, two)), acc + 1)
    in loop (n, 0) end

  fun modulusBytesN n = (bitLength n + 7) div 8
  fun modulusBytes (pub : pubkey) = modulusBytesN (#n pub)
  fun pubOf (k : privkey) : pubkey = { n = #n k, e = #e k }

  (* byte-wise XOR of two equal-length strings *)
  fun xorStr (a, b) =
    String.implode
      (List.tabulate (String.size a, fn i =>
         Char.chr (Word.toInt
           (Word.xorb (Word.fromInt (ordOf (a, i)), Word.fromInt (ordOf (b, i)))))))

  (* zero the leftmost [nbits] (0..7) bits of the first byte of s *)
  fun clearTopBits (s, nbits) =
    if nbits = 0 then s
    else
      let
        val mask = Word.toInt (Word.>> (0wxFF, Word.fromInt nbits))   (* 0xFF >> nbits *)
        val b0   = Word.toInt (Word.andb (Word.fromInt (ordOf (s, 0)), Word.fromInt mask))
      in byte b0 ^ String.extract (s, 1, NONE) end

  (* are the leftmost [nbits] (0..7) bits of the first byte of s all zero? *)
  fun topBitsZero (s, nbits) =
    nbits = 0 orelse ordOf (s, 0) = ordOf (clearTopBits (s, nbits), 0)

  (* ---- hashes ---- *)
  fun hashBytes SHA1   m = Sha1.digest m
    | hashBytes SHA256 m = Sha256.digest m
    | hashBytes SHA512 m = Sha512.digest m
  fun hashLen SHA1   = 20
    | hashLen SHA256 = 32
    | hashLen SHA512 = 64
  fun hashOid SHA1   = [1, 3, 14, 3, 2, 26]
    | hashOid SHA256 = [2, 16, 840, 1, 101, 3, 4, 2, 1]
    | hashOid SHA512 = [2, 16, 840, 1, 101, 3, 4, 2, 3]

  (* MGF1 (RFC 8017 App. B.2.1) with the given hash *)
  fun mgf1 (hash, seed, len) =
    let
      val hLen = hashLen hash
      fun loop (counter, acc, got) =
        if got >= len then String.substring (String.concat (List.rev acc), 0, len)
        else
          let val block = hashBytes hash (seed ^ i2osp (B.fromInt counter, 4))
          in loop (counter + 1, block :: acc, got + hLen) end
    in loop (0, [], 0) end

  (* ---- extended Euclid / modular inverse ---- *)
  (* inverse of a modulo m (m > 0), raising if a is not invertible *)
  fun modInverse (a, m) =
    let
      fun ext (r0, s0, r1, s1) =
        if B.compare (r1, zero) = EQUAL then (r0, s0)
        else
          let val q  = #1 (B.quotRem (r0, r1))
              val r2 = B.sub (r0, B.mul (q, r1))
              val s2 = B.sub (s0, B.mul (q, s1))
          in ext (r1, s1, r2, s2) end
      val (g, x) = ext (modNN (a, m), one, m, zero)
    in
      if B.compare (g, one) <> EQUAL then raise RSA "modInverse: value is not invertible"
      else modNN (x, m)
    end

  (* ---------------------------------------------------------------- *)
  (* RSA primitives                                                   *)
  (* ---------------------------------------------------------------- *)

  (* RSAEP / RSAVP1 : c = m^e mod n *)
  fun rsaPublic ({n, e} : pubkey, m) =
    if B.compare (m, zero) = LESS orelse B.compare (m, n) <> LESS
    then raise RSA "message representative out of range"
    else B.modpow (m, e, n)

  (* RSADP / RSASP1 via CRT : m = c^d mod n *)
  fun rsaPrivate (k : privkey, c) =
    let
      val { p, q, dp, dq, qinv, n, ... } = k
      val () = if B.compare (c, zero) = LESS orelse B.compare (c, n) <> LESS
               then raise RSA "ciphertext representative out of range" else ()
      val m1 = B.modpow (c, dp, p)
      val m2 = B.modpow (c, dq, q)
      val h  = modNN (B.mul (qinv, modNN (B.sub (m1, m2), p)), p)
    in B.add (m2, B.mul (q, h)) end

  (* ---------------------------------------------------------------- *)
  (* EMSA-PKCS1-v1_5 signatures (RFC 8017 sec. 8.2 / 9.2)             *)
  (* ---------------------------------------------------------------- *)

  fun digestInfo (hash, msg) =
    Asn1.encode
      (Asn1.Seq [ Asn1.Seq [ Asn1.Oid (hashOid hash), Asn1.Null ]
                , Asn1.Bytes (hashBytes hash msg) ])

  fun emsaPkcs1v15 (hash, msg, emLen) =
    let
      val t    = digestInfo (hash, msg)
      val tLen = String.size t
      val () = if emLen < tLen + 11
               then raise RSA "intended encoded message length too short" else ()
      val ps = String.implode (List.tabulate (emLen - tLen - 3, fn _ => Char.chr 0xFF))
    in byte 0 ^ byte 1 ^ ps ^ byte 0 ^ t end

  fun sign { priv : privkey, hash, msg } =
    let
      val k  = modulusBytesN (#n priv)
      val em = emsaPkcs1v15 (hash, msg, k)
    in i2osp (rsaPrivate (priv, os2ip em), k) end

  fun verify { pub : pubkey, hash, msg, sgn } =
    (let
       val k = modulusBytesN (#n pub)
     in
       String.size sgn = k
       andalso
       let val m  = rsaPublic (pub, os2ip sgn)
           val em = i2osp (m, k)
       in em = emsaPkcs1v15 (hash, msg, k) end
     end) handle _ => false

  (* ---------------------------------------------------------------- *)
  (* EMSA-PSS signatures (RFC 8017 sec. 8.1 / 9.1)                    *)
  (* ---------------------------------------------------------------- *)

  fun emsaPssEncode (hash, msg, salt, emBits) =
    let
      val hLen  = hashLen hash
      val sLen  = String.size salt
      val emLen = (emBits + 7) div 8
      val () = if emLen < hLen + sLen + 2 then raise RSA "PSS: encoding error" else ()
      val mHash  = hashBytes hash msg
      val mPrime = zeros 8 ^ mHash ^ salt
      val h      = hashBytes hash mPrime
      val ps     = zeros (emLen - sLen - hLen - 2)
      val db     = ps ^ byte 1 ^ salt                       (* emLen - hLen - 1 bytes *)
      val maskedDB  = xorStr (db, mgf1 (hash, h, emLen - hLen - 1))
      val maskedDB' = clearTopBits (maskedDB, 8 * emLen - emBits)
    in maskedDB' ^ h ^ byte 0xBC end

  fun signPss { priv : privkey, hash, salt, msg } =
    let
      val emBits = bitLength (#n priv) - 1
      val em = emsaPssEncode (hash, msg, salt, emBits)
    in i2osp (rsaPrivate (priv, os2ip em), modulusBytesN (#n priv)) end

  fun verifyPss { pub : pubkey, hash, saltLen, msg, sgn } =
    (let
       val n     = #n pub
       val k     = modulusBytesN n
       val emBits = bitLength n - 1
       val emLen  = (emBits + 7) div 8
       val hLen   = hashLen hash
     in
       String.size sgn = k
       andalso
       let
         val em = i2osp (rsaPublic (pub, os2ip sgn), emLen)
         val dbLen = emLen - hLen - 1
       in
         emLen >= hLen + saltLen + 2
         andalso ordOf (em, emLen - 1) = 0xBC
         andalso
         let
           val maskedDB = String.substring (em, 0, dbLen)
           val h        = String.substring (em, dbLen, hLen)
           val topBits  = 8 * emLen - emBits
         in
           topBitsZero (maskedDB, topBits)
           andalso
           let
             val db   = clearTopBits (xorStr (maskedDB, mgf1 (hash, h, dbLen)), topBits)
             val psN  = dbLen - saltLen - 1
             (* leading psN bytes must be 0x00, then a single 0x01 *)
             fun zeroPrefix i = i >= psN orelse (ordOf (db, i) = 0 andalso zeroPrefix (i + 1))
           in
             zeroPrefix 0 andalso ordOf (db, psN) = 1
             andalso
             let
               val salt   = String.extract (db, psN + 1, NONE)
               val mHash  = hashBytes hash msg
               val mPrime = zeros 8 ^ mHash ^ salt
             in h = hashBytes hash mPrime end
           end
         end
       end
     end) handle _ => false

  (* ---------------------------------------------------------------- *)
  (* EME-OAEP encryption (RFC 8017 sec. 7.1)                          *)
  (* ---------------------------------------------------------------- *)

  fun encryptOaep { pub : pubkey, hash, label, seed, msg } =
    let
      val n    = #n pub
      val k    = modulusBytesN n
      val hLen = hashLen hash
      val mLen = String.size msg
      val () = if String.size seed <> hLen then raise RSA "OAEP: seed must be hLen bytes" else ()
      val () = if mLen > k - 2 * hLen - 2 then raise RSA "OAEP: message too long" else ()
      val lHash = hashBytes hash label
      val db    = lHash ^ zeros (k - mLen - 2 * hLen - 2) ^ byte 1 ^ msg  (* k - hLen - 1 *)
      val maskedDB   = xorStr (db, mgf1 (hash, seed, k - hLen - 1))
      val maskedSeed = xorStr (seed, mgf1 (hash, maskedDB, hLen))
      val em = byte 0 ^ maskedSeed ^ maskedDB
    in i2osp (rsaPublic (pub, os2ip em), k) end

  fun decryptOaep { priv : privkey, hash, label, ct } =
    let
      val n    = #n priv
      val k    = modulusBytesN n
      val hLen = hashLen hash
      val () = if String.size ct <> k orelse k < 2 * hLen + 2
               then raise RSA "OAEP: decryption error" else ()
      val em   = i2osp (rsaPrivate (priv, os2ip ct), k)
      val lHash = hashBytes hash label
      val y          = ordOf (em, 0)
      val maskedSeed = String.substring (em, 1, hLen)
      val maskedDB   = String.substring (em, 1 + hLen, k - hLen - 1)
      val seed = xorStr (maskedSeed, mgf1 (hash, maskedDB, hLen))
      val db   = xorStr (maskedDB, mgf1 (hash, seed, k - hLen - 1))
      val lHash' = String.substring (db, 0, hLen)
      (* skip the PS zeros, require a single 0x01 separator *)
      fun findOne i =
        if i >= String.size db then raise RSA "OAEP: decryption error"
        else case ordOf (db, i) of
               1 => i
             | 0 => findOne (i + 1)
             | _ => raise RSA "OAEP: decryption error"
      val sep = findOne hLen
    in
      if y <> 0 orelse lHash' <> lHash then raise RSA "OAEP: decryption error"
      else String.extract (db, sep + 1, NONE)
    end

  (* ---------------------------------------------------------------- *)
  (* EME-PKCS1-v1_5 encryption (RFC 8017 sec. 7.2)                    *)
  (* ---------------------------------------------------------------- *)

  (* collect exactly [need] nonzero bytes from randomBytes *)
  fun nonZeroPad (randomBytes, need) =
    let
      fun go (acc, n) =
        if n = 0 then String.implode (List.rev acc)
        else
          let
            val chunk = randomBytes n
            val () = if String.size chunk = 0 then raise RSA "randomBytes returned no bytes" else ()
            fun take ([], acc, n) = (acc, n)
              | take (c :: cs, acc, n) =
                  if n = 0 then (acc, 0)
                  else if c = Char.chr 0 then take (cs, acc, n)
                  else take (cs, c :: acc, n - 1)
            val (acc', n') = take (String.explode chunk, acc, n)
          in go (acc', n') end
    in go ([], need) end

  fun encrypt { pub : pubkey, msg, randomBytes } =
    let
      val n = #n pub
      val k = modulusBytesN n
      val mLen = String.size msg
      val () = if mLen > k - 11 then raise RSA "message too long for PKCS#1 v1.5" else ()
      val ps = nonZeroPad (randomBytes, k - mLen - 3)
      val em = byte 0 ^ byte 2 ^ ps ^ byte 0 ^ msg
    in i2osp (rsaPublic (pub, os2ip em), k) end

  fun decrypt { priv : privkey, ct } =
    let
      val k = modulusBytesN (#n priv)
      val () = if String.size ct <> k orelse k < 11 then raise RSA "decryption error" else ()
      val em = i2osp (rsaPrivate (priv, os2ip ct), k)
      val () = if ordOf (em, 0) <> 0 orelse ordOf (em, 1) <> 2 then raise RSA "decryption error" else ()
      fun findZero i =
        if i >= k then raise RSA "decryption error"
        else if ordOf (em, i) = 0 then i else findZero (i + 1)
      val z = findZero 2
      val () = if z < 10 then raise RSA "decryption error" else ()   (* PS must be >= 8 *)
    in String.extract (em, z + 1, NONE) end

  (* ---------------------------------------------------------------- *)
  (* key generation                                                   *)
  (* ---------------------------------------------------------------- *)

  val mrRounds = B.fromInt 20   (* Miller-Rabin witness bases (clamped to table) *)
  fun nextPrime c = if B.isProbablePrime (c, mrRounds) then c else nextPrime (B.add (c, two))

  fun generate { bits, e, randomBytes } =
    let
      val () = if bits < 512 orelse bits mod 2 <> 0
               then raise RSA "generate: bits must be even and >= 512" else ()
      val () = if B.compare (e, B.fromInt 3) = LESS orelse isEven e
               then raise RSA "generate: e must be an odd integer > 1" else ()
      val pbits = bits div 2

      (* a random odd pbits-bit candidate with the top two bits set *)
      fun candidate () =
        let
          val nbytes = (pbits + 7) div 8
          val raw = randomBytes nbytes
          val () = if String.size raw < nbytes then raise RSA "randomBytes too short" else ()
          val x   = os2ip (String.substring (raw, 0, nbytes))
          val top = B.add (pow2 (pbits - 1), pow2 (pbits - 2))
          val c0  = B.add (top, modNN (x, pow2 (pbits - 2)))
        in if isEven c0 then B.add (c0, one) else c0 end

      (* search upward for a prime p with gcd(e, p-1) = 1 *)
      fun primeCoprime () =
        let
          fun search c =
            let val p = nextPrime c
            in if B.compare (B.gcd (e, B.sub (p, one)), one) = EQUAL then p
               else search (B.add (p, two))
            end
        in search (candidate ()) end

      val p0 = primeCoprime ()
      fun distinctQ () =
        let val q = primeCoprime ()
        in if B.compare (q, p0) = EQUAL then distinctQ () else q end
      val q0 = distinctQ ()
      val (p, q) = if B.compare (p0, q0) = LESS then (q0, p0) else (p0, q0)

      val n   = B.mul (p, q)
      val p1  = B.sub (p, one)
      val q1  = B.sub (q, one)
      val lam = #1 (B.divMod (B.mul (p1, q1), B.gcd (p1, q1)))   (* Carmichael lambda *)
      val d   = modInverse (e, lam)
    in
      { pub  = { n = n, e = e }
      , priv = { n = n, e = e, d = d, p = p, q = q
               , dp = modNN (d, p1), dq = modNN (d, q1), qinv = modInverse (q, p) } }
    end

  (* ---------------------------------------------------------------- *)
  (* DER / PEM key import & export                                    *)
  (* ---------------------------------------------------------------- *)

  val rsaOid = [1, 2, 840, 113549, 1, 1, 1]   (* rsaEncryption *)
  val rsaAlgId = Asn1.Seq [ Asn1.Oid rsaOid, Asn1.Null ]

  fun encodePublicDer ({ n, e } : pubkey) =
    Asn1.encode (Asn1.Seq [ Asn1.Int n, Asn1.Int e ])

  fun decodePublicDer s =
    case Asn1.decode s of
      Asn1.Seq [ Asn1.Int n, Asn1.Int e ] => { n = n, e = e }
    | _ => raise RSA "bad RSAPublicKey"

  fun encodePrivateDer (k : privkey) =
    Asn1.encode
      (Asn1.Seq [ Asn1.Int zero, Asn1.Int (#n k), Asn1.Int (#e k), Asn1.Int (#d k)
                , Asn1.Int (#p k), Asn1.Int (#q k)
                , Asn1.Int (#dp k), Asn1.Int (#dq k), Asn1.Int (#qinv k) ])

  fun decodePrivateDer s =
    case Asn1.decode s of
      Asn1.Seq [ Asn1.Int _, Asn1.Int n, Asn1.Int e, Asn1.Int d
               , Asn1.Int p, Asn1.Int q, Asn1.Int dp, Asn1.Int dq, Asn1.Int qinv ] =>
        { n = n, e = e, d = d, p = p, q = q, dp = dp, dq = dq, qinv = qinv }
    | _ => raise RSA "bad RSAPrivateKey"

  fun encodeSpkiDer (pub : pubkey) =
    Asn1.encode (Asn1.Seq [ rsaAlgId, Asn1.BitString (encodePublicDer pub) ])

  fun decodeSpkiDer s =
    case Asn1.decode s of
      Asn1.Seq (Asn1.Seq (Asn1.Oid oid :: _) :: Asn1.BitString bits :: _) =>
        if oid = rsaOid then decodePublicDer bits
        else raise RSA "SubjectPublicKeyInfo: not an RSA key"
    | _ => raise RSA "bad SubjectPublicKeyInfo"

  fun encodePkcs8Der (k : privkey) =
    Asn1.encode (Asn1.Seq [ Asn1.Int zero, rsaAlgId, Asn1.Bytes (encodePrivateDer k) ])

  fun decodePkcs8Der s =
    case Asn1.decode s of
      Asn1.Seq (Asn1.Int _ :: Asn1.Seq (Asn1.Oid oid :: _) :: Asn1.Bytes octets :: _) =>
        if oid = rsaOid then decodePrivateDer octets
        else raise RSA "PKCS#8 PrivateKeyInfo: not an RSA key"
    | _ => raise RSA "bad PKCS#8 PrivateKeyInfo"

  fun encodePublicPem  pub = Pem.encode { label = "PUBLIC KEY",  der = encodeSpkiDer pub }
  fun encodePrivatePem k   = Pem.encode { label = "PRIVATE KEY", der = encodePkcs8Der k }

  fun firstBlock s =
    case Pem.decode s of
      [] => raise RSA "no PEM block found"
    | (b :: _) => b

  fun decodePublicPem s =
    let val { label, der } = firstBlock s
    in
      if label = "PUBLIC KEY" then decodeSpkiDer der
      else if label = "RSA PUBLIC KEY" then decodePublicDer der
      else raise RSA ("unexpected PEM label for a public key: " ^ label)
    end

  fun decodePrivatePem s =
    let val { label, der } = firstBlock s
    in
      if label = "PRIVATE KEY" then decodePkcs8Der der
      else if label = "RSA PRIVATE KEY" then decodePrivateDer der
      else raise RSA ("unexpected PEM label for a private key: " ^ label)
    end
end
