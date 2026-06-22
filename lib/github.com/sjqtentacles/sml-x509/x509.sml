(* x509.sml

   X.509 v3 certificate parsing and RSA signature verification.

   The parser is a small, offset-aware DER reader (not the vendored Asn1
   decoder) for two reasons:

     1. Signatures cover the *verbatim* DER of the tbsCertificate.  Decoding to a
        datatype and re-encoding is not guaranteed to reproduce those bytes, so
        the reader hands back the exact source byte-slice of every element via
        [raw].

     2. Real certificates use ASN.1 types outside the Asn1 "common subset"
        (UTCTime / GeneralizedTime for validity, IA5String for SAN entries) and
        IMPLICIT primitive context tags (e.g. the SAN dNSName [2] and the
        authorityKeyIdentifier keyIdentifier [0]) -- the strict common-subset
        decoder rejects those by design.

   The vendored Asn1/Pem/Rsa/BigInt are still used: Pem to unwrap CERTIFICATE
   blocks, BigInt for the serial number, and Rsa for the actual signature
   verification (PKCS#1 v1.5 and PSS) over the captured tbs bytes. *)

structure X509 :> X509 =
struct
  exception X509 of string

  (* ===================== parsed types ===================== *)

  type time = { year : int, month : int, day : int
              , hour : int, minute : int, second : int }
  type validity = { notBefore : time, notAfter : time }
  type attribute = { oid : int list, value : string }
  type name = attribute list
  type basicConstraints = { ca : bool, pathLen : int option }
  type extension = { oid : int list, critical : bool, value : string }

  datatype sigAlg =
      Sha1WithRsa | Sha256WithRsa | Sha384WithRsa | Sha512WithRsa
    | RsaPss of { hash : Rsa.hash, saltLen : int }
    | EcdsaWithSha256 | EcdsaWithSha384 | EcdsaWithSha512
    | Ed25519Sig | UnknownSigAlg of int list

  datatype keyAlg =
      RsaKey | EcKey of int list | Ed25519Key | UnknownKeyAlg of int list

  datatype verifyResult = Verified | Failed | Unsupported of string
  datatype chainResult = ChainOk | ChainError of string

  (* The certificate record (kept abstract through the signature). *)
  type cert =
    { der            : string
    , tbsDer         : string
    , version        : int
    , serialContent  : string          (* raw INTEGER content octets *)
    , serial         : BigInt.int
    , sigAlg         : sigAlg
    , issuer         : name
    , issuerDer      : string          (* verbatim Name encoding *)
    , subject        : name
    , subjectDer     : string
    , validity       : validity
    , spkiDer        : string
    , keyAlg         : keyAlg
    , signatureValue : string
    , extensions     : extension list }

  (* ===================== DER reader ===================== *)

  fun byteAt (s, i) = Char.ord (String.sub (s, i))

  (* a TLV node: tag class/number, the constructed bit, and byte offsets into
     the source string.  [contentOff]/[contentLen] delimit the contents;
     [start]/[endOff] delimit the whole element (header + contents). *)
  type node = { cls : int, constructed : bool, tag : int
              , start : int, contentOff : int, contentLen : int, endOff : int }

  (* read a DEFINITE length at [pos]; returns (length, posAfterLength) *)
  fun readLen (s, pos) =
    let val size = String.size s
        val () = if pos >= size then raise X509 "truncated length" else ()
        val b0 = byteAt (s, pos)
    in
      if b0 < 0x80 then (b0, pos + 1)
      else
        let val n = b0 - 0x80
            val () = if n = 0 then raise X509 "indefinite length not allowed" else ()
            val () = if pos + n >= size then raise X509 "truncated long-form length" else ()
            fun loop (i, acc) =
              if i = n then acc else loop (i + 1, acc * 256 + byteAt (s, pos + 1 + i))
        in (loop (0, 0), pos + 1 + n) end
    end

  (* read one TLV node starting at [pos] *)
  fun readTLV (s, pos) : node =
    let
      val size = String.size s
      val () = if pos >= size then raise X509 "truncated identifier" else ()
      val id = byteAt (s, pos)
      val cls = id div 64
      val constructed = (id div 32) mod 2 = 1
      val low = id mod 32
      (* high-tag-number form: tag carried in following base-128 octets *)
      val (tag, idEnd) =
        if low <> 31 then (low, pos + 1)
        else
          let fun loop (i, acc) =
                let val () = if i >= size then raise X509 "truncated high tag" else ()
                    val b = byteAt (s, i)
                    val acc' = acc * 128 + (b mod 128)
                in if b < 0x80 then (acc', i + 1) else loop (i + 1, acc') end
          in loop (pos + 1, 0) end
      val (len, contentOff) = readLen (s, idEnd)
      val endOff = contentOff + len
      val () = if endOff > size then raise X509 "length exceeds input" else ()
    in
      { cls = cls, constructed = constructed, tag = tag
      , start = pos, contentOff = contentOff, contentLen = len, endOff = endOff }
    end

  (* the contents octets of a node *)
  fun content (s, (n : node)) = String.substring (s, #contentOff n, #contentLen n)
  (* the verbatim whole-element octets (header + contents) *)
  fun raw (s, (n : node)) = String.substring (s, #start n, #endOff n - #start n)

  (* the child TLVs of a constructed node, in order *)
  fun children (s, (n : node)) =
    let val stop = #endOff n
        fun loop pos =
          if pos >= stop then []
          else let val c = readTLV (s, pos) in c :: loop (#endOff c) end
    in loop (#contentOff n) end

  (* ---- small primitive decoders over a node ---- *)

  (* unsigned big-endian host int from a node's contents (for small fields) *)
  fun uintOf (s, n) =
    let val c = content (s, n)
        fun loop (i, acc) =
          if i >= String.size c then acc
          else loop (i + 1, acc * 256 + Char.ord (String.sub (c, i)))
    in loop (0, 0) end

  fun boolOf (s, n) = String.size (content (s, n)) > 0
                      andalso byteAt (content (s, n), 0) <> 0

  (* OBJECT IDENTIFIER arcs from a node's contents *)
  fun oidOf (s, n) =
    let
      val c = content (s, n)
      val len = String.size c
      val () = if len = 0 then raise X509 "empty OID" else ()
      fun readSub (j, v) =
        if j >= len then raise X509 "truncated OID"
        else let val b = byteAt (c, j)
                 val v' = v * 128 + (b mod 128)
             in if b < 0x80 then (v', j + 1) else readSub (j + 1, v') end
      fun loop (i, acc) =
        if i >= len then List.rev acc
        else let val (v, nx) = readSub (i, 0) in loop (nx, v :: acc) end
      val subs = loop (0, [])
    in
      case subs of
        (first :: rest) =>
          let val (a0, a1) =
                if first < 40 then (0, first)
                else if first < 80 then (1, first - 40)
                else (2, first - 80)
          in a0 :: a1 :: rest end
      | [] => raise X509 "empty OID"
    end

  (* BIT STRING contents (drop the leading unused-bit count octet) *)
  fun bitStringOf (s, n) =
    let val c = content (s, n)
    in if String.size c = 0 then "" else String.extract (c, 1, NONE) end

  val b256 = BigInt.fromInt 256
  fun bigUnsigned bytes =
    let fun loop (i, acc) =
          if i >= String.size bytes then acc
          else loop (i + 1, BigInt.add (BigInt.mul (acc, b256),
                                        BigInt.fromInt (Char.ord (String.sub (bytes, i)))))
    in loop (0, BigInt.fromInt 0) end

  fun toHexLower s =
    let val d = "0123456789abcdef"
        fun hx c = let val x = Char.ord c
                   in String.implode [String.sub (d, x div 16), String.sub (d, x mod 16)] end
    in String.concat (List.map hx (String.explode s)) end

  (* ===================== OID tables ===================== *)

  val oidCommonName    = [2,5,4,3]
  val oidBasicConstr   = [2,5,29,19]
  val oidKeyUsage      = [2,5,29,15]
  val oidExtKeyUsage   = [2,5,29,37]
  val oidSubjectAltName= [2,5,29,17]
  val oidSubjectKeyId  = [2,5,29,14]
  val oidAuthKeyId     = [2,5,29,35]

  fun hashOfOid oid =
    if oid = [1,3,14,3,2,26] then SOME Rsa.SHA1
    else if oid = [2,16,840,1,101,3,4,2,1] then SOME Rsa.SHA256
    else if oid = [2,16,840,1,101,3,4,2,3] then SOME Rsa.SHA512
    else NONE

  (* ===================== field parsers ===================== *)

  fun parseName (s, nameNode) : name =
    let
      val rdns = children (s, nameNode)              (* each is a SET *)
      fun fromAtv atvNode =
        case children (s, atvNode) of
          (oidN :: valN :: _) => { oid = oidOf (s, oidN), value = content (s, valN) }
        | _ => raise X509 "malformed AttributeTypeAndValue"
      fun fromSet setNode = List.map fromAtv (children (s, setNode))
    in List.concat (List.map fromSet rdns) end

  fun parseTime (s, tNode) : time =
    let
      val c = content (s, tNode)
      fun d2 i = (byteAt (c, i) - 48) * 10 + (byteAt (c, i + 1) - 48)
    in
      if #tag tNode = 23 then                          (* UTCTime YYMMDDHHMMSSZ *)
        let val yy = d2 0
            val year = if yy < 50 then 2000 + yy else 1900 + yy
        in { year = year, month = d2 2, day = d2 4
           , hour = d2 6, minute = d2 8, second = d2 10 } end
      else if #tag tNode = 24 then                     (* GeneralizedTime YYYYMMDD... *)
        { year = d2 0 * 100 + d2 2, month = d2 4, day = d2 6
        , hour = d2 8, minute = d2 10, second = d2 12 }
      else raise X509 "unexpected time type"
    end

  fun parseValidity (s, vNode) : validity =
    case children (s, vNode) of
      (nb :: na :: _) => { notBefore = parseTime (s, nb), notAfter = parseTime (s, na) }
    | _ => raise X509 "malformed Validity"

  (* RSASSA-PSS-params (RFC 4055): pull the hash and salt length, with the
     RFC defaults (SHA-1, salt 20) when absent. *)
  fun parsePssParams (s, paramsNode) =
    let
      val kids = children (s, paramsNode)
      fun scan ([], hash, salt) = { hash = hash, saltLen = salt }
        | scan (k :: rest, hash, salt) =
            if #cls k = 2 andalso #tag k = 0 then          (* [0] hashAlgorithm *)
              (case children (s, k) of
                 (alg :: _) =>
                   (case children (s, alg) of
                      (oidN :: _) =>
                        (case hashOfOid (oidOf (s, oidN)) of
                           SOME h => scan (rest, h, salt)
                         | NONE => scan (rest, hash, salt))
                    | _ => scan (rest, hash, salt))
               | _ => scan (rest, hash, salt))
            else if #cls k = 2 andalso #tag k = 2 then     (* [2] saltLength *)
              (case children (s, k) of
                 (intN :: _) => scan (rest, hash, uintOf (s, intN))
               | _ => scan (rest, hash, salt))
            else scan (rest, hash, salt)
    in scan (kids, Rsa.SHA1, 20) end

  fun parseSigAlg (s, algNode) : sigAlg =
    case children (s, algNode) of
      (oidN :: rest) =>
        let val oid = oidOf (s, oidN)
        in
          if oid = [1,2,840,113549,1,1,5]  then Sha1WithRsa
          else if oid = [1,2,840,113549,1,1,11] then Sha256WithRsa
          else if oid = [1,2,840,113549,1,1,12] then Sha384WithRsa
          else if oid = [1,2,840,113549,1,1,13] then Sha512WithRsa
          else if oid = [1,2,840,113549,1,1,10] then
            (case rest of
               (p :: _) => RsaPss (parsePssParams (s, p))
             | [] => RsaPss { hash = Rsa.SHA1, saltLen = 20 })
          else if oid = [1,2,840,10045,4,3,2] then EcdsaWithSha256
          else if oid = [1,2,840,10045,4,3,3] then EcdsaWithSha384
          else if oid = [1,2,840,10045,4,3,4] then EcdsaWithSha512
          else if oid = [1,3,101,112] then Ed25519Sig
          else UnknownSigAlg oid
        end
    | _ => raise X509 "malformed AlgorithmIdentifier"

  fun parseKeyAlg (s, spkiNode) : keyAlg =
    case children (s, spkiNode) of
      (algN :: _) =>
        (case children (s, algN) of
           (oidN :: rest) =>
             let val oid = oidOf (s, oidN)
             in
               if oid = [1,2,840,113549,1,1,1] then RsaKey
               else if oid = [1,2,840,10045,2,1] then
                 (case rest of
                    (p :: _) => (EcKey (oidOf (s, p)) handle _ => EcKey [])
                  | [] => EcKey [])
               else if oid = [1,3,101,112] then Ed25519Key
               else UnknownKeyAlg oid
             end
         | _ => raise X509 "malformed SPKI algorithm")
    | _ => raise X509 "malformed SubjectPublicKeyInfo"

  fun parseExtensions (s, extsSeqNode) : extension list =
    let
      fun fromExt extNode =
        case children (s, extNode) of
          (oidN :: rest) =>
            let
              val oid = oidOf (s, oidN)
              val (critical, valNode) =
                case rest of
                  (b :: v :: _) => if #tag b = 1 andalso #cls b = 0
                                   then (boolOf (s, b), v) else (false, b)
                | (v :: _) => (false, v)
                | [] => raise X509 "extension missing value"
            in { oid = oid, critical = critical, value = content (s, valNode) } end
        | _ => raise X509 "malformed Extension"
    in List.map fromExt (children (s, extsSeqNode)) end

  (* ===================== top-level parse ===================== *)

  fun parse der : cert =
    let
      val certN = readTLV (der, 0)
      val () = if #endOff certN <> String.size der then raise X509 "trailing bytes" else ()
      val (tbsN, algN, sigN) =
        case children (der, certN) of
          (a :: b :: c :: _) => (a, b, c)
        | _ => raise X509 "Certificate is not a 3-element SEQUENCE"

      val tbsDer = raw (der, tbsN)
      val sigAlg = parseSigAlg (der, algN)
      val signatureValue = bitStringOf (der, sigN)

      val tbsKids = children (der, tbsN)
      (* optional [0] EXPLICIT version *)
      val (version, afterVer) =
        case tbsKids of
          (k :: ks) =>
            if #cls k = 2 andalso #tag k = 0 then
              (case children (der, k) of
                 (vN :: _) => (uintOf (der, vN), ks)
               | [] => (0, ks))
            else (0, tbsKids)
        | [] => raise X509 "empty tbsCertificate"

      val (serialN, issuerN, validN, subjectN, spkiN, moreKids) =
        case afterVer of
          (serialN :: sigInnerN :: issuerN :: validN :: subjectN :: spkiN :: more) =>
            (ignore sigInnerN; (serialN, issuerN, validN, subjectN, spkiN, more))
        | _ => raise X509 "tbsCertificate missing required fields"

      val serialContent = content (der, serialN)
      (* magnitude (strip a single leading 0x00 sign octet) for hex + value *)
      val serialMag =
        if String.size serialContent > 1 andalso byteAt (serialContent, 0) = 0
        then String.extract (serialContent, 1, NONE) else serialContent

      val extensions =
        case List.find (fn k => #cls k = 2 andalso #tag k = 3) moreKids of
          SOME ext3 =>
            (case children (der, ext3) of
               (seqN :: _) => parseExtensions (der, seqN)
             | [] => [])
        | NONE => []
    in
      { der = der
      , tbsDer = tbsDer
      , version = version
      , serialContent = serialContent
      , serial = bigUnsigned serialMag
      , sigAlg = sigAlg
      , issuer = parseName (der, issuerN)
      , issuerDer = raw (der, issuerN)
      , subject = parseName (der, subjectN)
      , subjectDer = raw (der, subjectN)
      , validity = parseValidity (der, validN)
      , spkiDer = raw (der, spkiN)
      , keyAlg = parseKeyAlg (der, spkiN)
      , signatureValue = signatureValue
      , extensions = extensions }
    end

  fun parsePem pem =
    let val blocks = Pem.decode pem
        val certs = List.filter (fn b => #label b = "CERTIFICATE") blocks
    in List.map (fn b => parse (#der b)) certs end

  (* ===================== time ===================== *)

  fun compareTime (a : time, b : time) =
    let
      fun cmp (x, y) = Int.compare (x, y)
      fun chain (EQUAL, k) = k ()
        | chain (ord, _) = ord
    in
      chain (cmp (#year a, #year b), fn () =>
      chain (cmp (#month a, #month b), fn () =>
      chain (cmp (#day a, #day b), fn () =>
      chain (cmp (#hour a, #hour b), fn () =>
      chain (cmp (#minute a, #minute b), fn () =>
             cmp (#second a, #second b))))))
    end

  fun pad2 n = (if n < 10 then "0" else "") ^ Int.toString n
  fun pad4 n = (if n < 1000 then "0" else "") ^ (if n < 100 then "0" else "")
               ^ (if n < 10 then "0" else "") ^ Int.toString n
  fun timeToString (t : time) =
    pad4 (#year t) ^ "-" ^ pad2 (#month t) ^ "-" ^ pad2 (#day t) ^ "T"
    ^ pad2 (#hour t) ^ ":" ^ pad2 (#minute t) ^ ":" ^ pad2 (#second t) ^ "Z"

  (* ===================== names ===================== *)

  fun commonName (n : name) =
    case List.find (fn a => #oid a = oidCommonName) n of
      SOME a => SOME (#value a)
    | NONE => NONE

  fun shortOid oid =
    if oid = [2,5,4,3] then "CN"
    else if oid = [2,5,4,10] then "O"
    else if oid = [2,5,4,11] then "OU"
    else if oid = [2,5,4,6] then "C"
    else if oid = [2,5,4,7] then "L"
    else if oid = [2,5,4,8] then "ST"
    else if oid = [1,2,840,113549,1,9,1] then "emailAddress"
    else String.concatWith "." (List.map Int.toString oid)

  fun nameToString (n : name) =
    String.concatWith ","
      (List.map (fn a => shortOid (#oid a) ^ "=" ^ #value a) (List.rev n))

  (* ===================== accessors ===================== *)

  fun version (c : cert) = #version c
  fun serialNumber (c : cert) = #serial c
  fun serialHex (c : cert) =
    let val m = #serialContent c
        val m = if String.size m > 1 andalso byteAt (m, 0) = 0
                then String.extract (m, 1, NONE) else m
    in toHexLower m end
  fun signatureAlg (c : cert) = #sigAlg c
  fun issuer (c : cert) = #issuer c
  fun subject (c : cert) = #subject c
  fun validity (c : cert) = #validity c
  fun notBefore (c : cert) = #notBefore (#validity c)
  fun notAfter (c : cert) = #notAfter (#validity c)
  fun publicKeyAlg (c : cert) = #keyAlg c
  fun tbsCertificateDer (c : cert) = #tbsDer c
  fun subjectPublicKeyInfoDer (c : cert) = #spkiDer c
  fun signatureValue (c : cert) = #signatureValue c
  fun extensions (c : cert) = #extensions c
  fun findExtension (c : cert) oid =
    List.find (fn e => #oid e = oid) (#extensions c)

  fun rsaPublicKey (c : cert) =
    case #keyAlg c of
      RsaKey => (SOME (Rsa.decodeSpkiDer (#spkiDer c)) handle _ => NONE)
    | _ => NONE

  (* ---- extension-derived accessors ---- *)

  fun basicConstraints (c : cert) =
    case findExtension c oidBasicConstr of
      NONE => NONE
    | SOME e =>
        let val v = #value e
            val seqN = readTLV (v, 0)
            val kids = children (v, seqN)
            val ca = case kids of
                       (b :: _) => if #tag b = 1 then boolOf (v, b) else false
                     | [] => false
            val pathLen =
              case List.find (fn k => #tag k = 2 andalso #cls k = 0) kids of
                SOME iN => SOME (uintOf (v, iN))
              | NONE => NONE
        in SOME { ca = ca, pathLen = pathLen } end
        handle _ => NONE

  fun isCA (c : cert) =
    case basicConstraints c of SOME {ca, ...} => ca | NONE => false

  fun keyUsage (c : cert) =
    case findExtension c oidKeyUsage of
      NONE => []
    | SOME e =>
        let
          val v = #value e
          val bsN = readTLV (v, 0)
          val bits = content (v, bsN)               (* unused-count + bytes *)
          val names = [ "digitalSignature", "nonRepudiation", "keyEncipherment"
                      , "dataEncipherment", "keyAgreement", "keyCertSign"
                      , "cRLSign", "encipherOnly", "decipherOnly" ]
          fun bitSet i =
            let val byteIdx = 1 + (i div 8)        (* +1 to skip unused-count *)
            in byteIdx < String.size bits
               andalso (byteAt (bits, byteIdx) div (Word.toInt (Word.<< (0w1, Word.fromInt (7 - (i mod 8)))))) mod 2 = 1
            end
          fun pick (_, []) = []
            | pick (i, nm :: rest) = (if bitSet i then [nm] else []) @ pick (i + 1, rest)
        in pick (0, names) end
        handle _ => []

  fun extKeyUsage (c : cert) =
    case findExtension c oidExtKeyUsage of
      NONE => []
    | SOME e =>
        let
          val v = #value e
          val seqN = readTLV (v, 0)
          fun nameOf oid =
            if oid = [1,3,6,1,5,5,7,3,1] then "serverAuth"
            else if oid = [1,3,6,1,5,5,7,3,2] then "clientAuth"
            else if oid = [1,3,6,1,5,5,7,3,3] then "codeSigning"
            else if oid = [1,3,6,1,5,5,7,3,4] then "emailProtection"
            else if oid = [1,3,6,1,5,5,7,3,8] then "timeStamping"
            else if oid = [1,3,6,1,5,5,7,3,9] then "OCSPSigning"
            else String.concatWith "." (List.map Int.toString oid)
        in List.map (fn k => nameOf (oidOf (v, k))) (children (v, seqN)) end
        handle _ => []

  fun dnsNames (c : cert) =
    case findExtension c oidSubjectAltName of
      NONE => []
    | SOME e =>
        let val v = #value e
            val seqN = readTLV (v, 0)
        in List.map (fn k => content (v, k))
             (List.filter (fn k => #cls k = 2 andalso #tag k = 2) (children (v, seqN)))
        end
        handle _ => []

  fun subjectKeyId (c : cert) =
    case findExtension c oidSubjectKeyId of
      NONE => NONE
    | SOME e => (SOME (content (#value e, readTLV (#value e, 0))) handle _ => NONE)

  fun authorityKeyId (c : cert) =
    case findExtension c oidAuthKeyId of
      NONE => NONE
    | SOME e =>
        let val v = #value e
            val seqN = readTLV (v, 0)
        in case List.find (fn k => #cls k = 2 andalso #tag k = 0) (children (v, seqN)) of
             SOME k => SOME (content (v, k))
           | NONE => NONE
        end
        handle _ => NONE

  (* ===================== verification ===================== *)

  fun verifySignature { cert : cert, issuer : cert } =
    case rsaPublicKey issuer of
      NONE => Unsupported "issuer key is not RSA"
    | SOME pub =>
        let
          val msg = #tbsDer cert
          val sgn = #signatureValue cert
          fun pkcs1 h = (if Rsa.verify { pub = pub, hash = h, msg = msg, sgn = sgn }
                         then Verified else Failed) handle _ => Failed
        in
          case #sigAlg cert of
            Sha1WithRsa   => pkcs1 Rsa.SHA1
          | Sha256WithRsa => pkcs1 Rsa.SHA256
          | Sha512WithRsa => pkcs1 Rsa.SHA512
          | Sha384WithRsa => Unsupported "SHA-384 not supported by sml-rsa"
          | RsaPss { hash, saltLen } =>
              ((if Rsa.verifyPss { pub = pub, hash = hash, saltLen = saltLen
                                 , msg = msg, sgn = sgn }
                then Verified else Failed) handle _ => Failed)
          | EcdsaWithSha256 => Unsupported "ECDSA verification is out of scope"
          | EcdsaWithSha384 => Unsupported "ECDSA verification is out of scope"
          | EcdsaWithSha512 => Unsupported "ECDSA verification is out of scope"
          | Ed25519Sig      => Unsupported "Ed25519 verification is out of scope"
          | UnknownSigAlg _ => Unsupported "unknown signature algorithm"
        end

  fun verifySelfSigned (c : cert) = verifySignature { cert = c, issuer = c }

  (* ===================== path validation ===================== *)

  fun verifyChain { cert : cert, intermediates, roots, time } =
    let
      fun timeOk (c : cert) =
        let val { notBefore, notAfter } = #validity c
        in compareTime (notBefore, time) <> GREATER
           andalso compareTime (time, notAfter) <> GREATER end

      fun isTrustedRoot (c : cert) =
        List.exists (fn r => #der r = #der c) roots

      fun verOk (c, iss) = verifySignature { cert = c, issuer = iss } = Verified

      fun loop (c : cert, fuel) =
        if fuel <= 0 then ChainError "chain too long (possible loop)"
        else if not (timeOk c) then ChainError "certificate outside its validity window"
        else if #issuerDer c = #subjectDer c andalso isTrustedRoot c then
          (if verifySelfSigned c = Verified then ChainOk
           else ChainError "trusted root self-signature does not verify")
        else
          case List.find (fn r => #subjectDer r = #issuerDer c) roots of
            SOME r =>
              if not (isCA r) then ChainError "issuer is not a CA"
              else if not (timeOk r) then ChainError "issuer outside its validity window"
              else if verOk (c, r) then ChainOk
              else ChainError "signature does not verify against trusted root"
          | NONE =>
              (case List.find (fn i => #subjectDer i = #issuerDer c) intermediates of
                 SOME i =>
                   if not (isCA i) then ChainError "intermediate is not a CA"
                   else if not (verOk (c, i)) then
                     ChainError "signature does not verify against intermediate"
                   else loop (i, fuel - 1)
               | NONE => ChainError "no issuer certificate found")
    in
      loop (cert, List.length intermediates + List.length roots + 2)
    end
end
