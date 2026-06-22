(* x509.sig

   X.509 v3 certificate parsing and RSA signature verification in pure
   Standard ML.

   This library decodes DER- and PEM-encoded X.509 certificates (RFC 5280)
   into a structured [cert] value, exposes the common fields and v3 extensions
   through accessors, and verifies certificate signatures whose issuer key is
   RSA -- both RSASSA-PKCS1-v1_5 and RSASSA-PSS -- by delegating to the vendored
   sml-rsa.  A small path-validation helper ([verifyChain]) checks a leaf up to
   a set of trusted roots: issuer/subject linkage, validity windows against an
   injected "current time", CA basic-constraints, and the RSA signature on every
   link.

   Byte convention.  Every encoded value -- the certificate, the
   tbsCertificate, the subjectPublicKeyInfo, signature bytes, key identifiers --
   is a raw [string]: one byte per [char], codepoints 0..255.  Arbitrary
   precision integers (the serial number) are carried by the vendored
   [BigInt] (sml-bigint).

   Determinism.  Nothing here reads the clock, the OS RNG, or any global state.
   Validity checking takes the current time as an explicit [time] argument, so
   the whole library is reproducible and byte-identical under MLton and Poly/ML.

   The exact signed bytes.  A signature covers the *original* DER encoding of
   the tbsCertificate, which is not guaranteed to survive a decode/re-encode
   round trip.  [tbsCertificateDer] therefore returns the verbatim byte slice of
   the tbsCertificate as it appeared in the input, so RSA verification is exact.

   Scope.  Signature *verification* is implemented for RSA issuer keys only.
   EC (ECDSA) and Ed25519 certificates still PARSE -- their public keys and
   signature algorithms are recognised -- but verification of them returns
   [Unsupported]: NIST P-256/P-384 curve arithmetic does not yet exist in the
   ecosystem (a future sml-p256), and secp256k1 is not the curve real-world
   certificates use.  This is a roadmap item, not a parsing limitation. *)

signature X509 =
sig
  (* Raised on malformed input that cannot be parsed as a certificate. *)
  exception X509 of string

  (* ---- parsed time ----

     A calendar instant decoded from an ASN.1 UTCTime or GeneralizedTime, in
     UTC ("Z").  UTCTime two-digit years follow RFC 5280: 00..49 -> 2000..2049,
     50..99 -> 1950..1999.  [compareTime] orders chronologically, so callers can
     supply their own "now" and compare it against [notBefore]/[notAfter]. *)
  type time = { year : int, month : int, day : int
              , hour : int, minute : int, second : int }
  val compareTime : time * time -> order
  (* "YYYY-MM-DDTHH:MM:SSZ" rendering (stable, for display and tests). *)
  val timeToString : time -> string

  type validity = { notBefore : time, notAfter : time }

  (* ---- distinguished names ----

     A Name is a sequence of relative distinguished names; we flatten it to the
     list of its attribute/value pairs in order.  [oid] is the attribute type
     (e.g. 2.5.4.3 = commonName) and [value] the decoded directory-string. *)
  type attribute = { oid : int list, value : string }
  type name = attribute list
  (* The first commonName (2.5.4.3) attribute, if any. *)
  val commonName : name -> string option
  (* A one-line RFC 4514-ish rendering ("CN=...,O=...,C=..."), most-specific
     first, for display and tests. *)
  val nameToString : name -> string

  (* ---- algorithms ---- *)
  datatype sigAlg =
      Sha1WithRsa
    | Sha256WithRsa
    | Sha384WithRsa
    | Sha512WithRsa
    | RsaPss of { hash : Rsa.hash, saltLen : int }
    | EcdsaWithSha256
    | EcdsaWithSha384
    | EcdsaWithSha512
    | Ed25519Sig
    | UnknownSigAlg of int list

  datatype keyAlg =
      RsaKey
    | EcKey of int list          (* named-curve OID *)
    | Ed25519Key
    | UnknownKeyAlg of int list

  (* ---- extensions ---- *)
  type basicConstraints = { ca : bool, pathLen : int option }

  (* A raw extension: its OID, the critical flag, and the verbatim extnValue
     OCTET STRING contents (the inner DER). *)
  type extension = { oid : int list, critical : bool, value : string }

  (* ---- the certificate ---- *)
  type cert

  (* Decode a single DER certificate; raises [X509] on malformed input. *)
  val parse : string -> cert
  (* Decode every CERTIFICATE block in a PEM document, in order. *)
  val parsePem : string -> cert list

  (* ---- core field accessors ---- *)
  (* X.509 version as the raw tag value: 0 = v1, 1 = v2, 2 = v3. *)
  val version          : cert -> int
  val serialNumber     : cert -> BigInt.int
  (* Serial as lowercase hex (big-endian, no sign byte), matching the usual
     "openssl x509 -serial" digits in lower case. *)
  val serialHex        : cert -> string
  val signatureAlg     : cert -> sigAlg
  val issuer           : cert -> name
  val subject          : cert -> name
  val validity         : cert -> validity
  val notBefore        : cert -> time
  val notAfter         : cert -> time
  val publicKeyAlg     : cert -> keyAlg

  (* ---- raw DER slices ---- *)
  (* The verbatim DER of the tbsCertificate -- the exact bytes the signature
     was computed over. *)
  val tbsCertificateDer : cert -> string
  (* The verbatim DER of the subjectPublicKeyInfo (suitable for
     [Rsa.decodeSpkiDer]). *)
  val subjectPublicKeyInfoDer : cert -> string
  (* The signature BIT STRING contents (the signature value bytes). *)
  val signatureValue   : cert -> string

  (* ---- public key ---- *)
  (* The issuer-checkable RSA public key, when the SPKI is RSA; NONE otherwise
     (EC / Ed25519 / unknown). *)
  val rsaPublicKey     : cert -> Rsa.pubkey option

  (* ---- extensions ---- *)
  val extensions       : cert -> extension list
  val findExtension    : cert -> int list -> extension option
  val basicConstraints : cert -> basicConstraints option
  (* Convenience: true iff a basicConstraints extension is present with CA TRUE. *)
  val isCA             : cert -> bool
  (* keyUsage bit names that are set, in RFC 5280 order, e.g.
     ["digitalSignature","keyEncipherment"]. *)
  val keyUsage         : cert -> string list
  (* extKeyUsage purposes: well-known ones as names (serverAuth, clientAuth,
     codeSigning, emailProtection, timeStamping, OCSPSigning), others as a
     dotted OID string. *)
  val extKeyUsage      : cert -> string list
  (* subjectAltName dNSName entries. *)
  val dnsNames         : cert -> string list
  val subjectKeyId     : cert -> string option   (* raw key-id bytes *)
  val authorityKeyId   : cert -> string option   (* raw keyIdentifier bytes *)

  (* ---- signature verification ---- *)
  datatype verifyResult =
      Verified
    | Failed                 (* RSA verification ran and rejected the signature *)
    | Unsupported of string  (* non-RSA issuer key / algorithm (EC, Ed25519...) *)

  (* Verify [cert]'s signature using [issuer]'s public key.  RSA issuer keys are
     verified (PKCS#1 v1.5 or PSS, per [cert]'s signatureAlgorithm); any other
     issuer key yields [Unsupported]. *)
  val verifySignature : { cert : cert, issuer : cert } -> verifyResult
  (* Verify a self-signed certificate against its own public key. *)
  val verifySelfSigned : cert -> verifyResult

  (* ---- path validation ---- *)
  datatype chainResult =
      ChainOk
    | ChainError of string

  (* Validate [cert] (the leaf) up to a trusted [roots] set, using [intermediates]
     to bridge the gap.  Checks, for every link from the leaf to a self-signed
     trusted root:
       - issuer/subject name linkage,
       - the validity window contains [time] (notBefore <= time <= notAfter),
       - every non-leaf certificate asserts CA = TRUE in basicConstraints,
       - the RSA signature verifies against the issuer's key.
     Returns [ChainOk] on success or [ChainError why] otherwise.  Roots are
     trusted by identity; a root's own (self-signed) signature is still checked. *)
  val verifyChain : { cert : cert
                    , intermediates : cert list
                    , roots : cert list
                    , time : time } -> chainResult
end
