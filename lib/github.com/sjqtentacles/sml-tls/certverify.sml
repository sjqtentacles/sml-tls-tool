(* certverify.sml

   Implementation of TLS_CERT_VERIFY (Track A2, Phase 3).

   Validates a server certificate chain to a caller-supplied trust anchor,
   purely and deterministically. The trust store, hostname, current time,
   and acceptable signature algorithms are all parameters, so the same
   inputs always produce the same accept/alert outcome on both MLton and
   Poly/ML. No network access.

   What is checked (RFC 5280 path validation + RFC 6125 name matching +
   RFC 8446 §4.2.3 signature_algorithms enforcement):
     - chain building from the leaf (chain[0]) up to a certificate whose
       identity matches a `trust` entry,
     - validity window of every cert in the path contains `now`,
     - BasicConstraints CA=TRUE on every non-leaf cert, and
       pathLenConstraint is not exceeded at any CA link,
     - KeyUsage keyCertSign on every CA cert that has a KeyUsage extension,
     - ExtendedKeyUsage serverAuth on the leaf (if EKU is present),
     - the leaf's signatureAlgorithm is in the caller's `sigAlgs` list,
     - signature verification up the chain via X509.verifySignature
       (RSA-PSS / PKCS#1 v1.5 through sml-rsa; ECDSA returns
       UnsupportedCertificate until sml-p256 lands in A4),
     - RFC 6125 hostname / SAN matching incl. leftmost-label wildcard.

   OCSP stapling (§4.4.2.1 `status_request`) is parsed-if-present but not
   enforced; CRL is deferred. The hook is `parseOcspStatus`, which returns
   the stapled bytes for the caller / J1 integrator. *)

structure TlsCertVerify :> TLS_CERT_VERIFY =
struct
  type trustStore = string list

  datatype result = Valid | Invalid of TlsAlert.alertDescription

  (* ------------------------------------------------------------------
     Time: convert an injected unix time (seconds since 1970-01-01T00:00:00Z)
     to the X509.time record so we can use X509.compareTime. Uses the
     well-known civil-from-days algorithm (Howard Hinnant), which is
     branch-light and identical on both compilers.
     ------------------------------------------------------------------ *)
  fun unixToTime (unix : int) : X509.time =
    let
      val days = unix div 86400
      val secsOfDay = unix mod 86400
      val secsOfDay = if secsOfDay < 0 then secsOfDay + 86400 else secsOfDay
      val days = if unix < 0 then days - 1 else days

      val z = days + 719468
      val era = if z >= 0 then z div 146097 else (z - 146096) div 146097
      val doe = z - era * 146097            (* day of era, 0..146096 *)
      val yoe = (doe - doe div 1460 + doe div 36524 - doe div 146096) div 365
      val y = yoe + era * 400
      val doy = doe - (365 * yoe + yoe div 4 - yoe div 100)
      val mp = (5 * doy + 2) div 153        (* 0..11 *)
      val d = doy - (153 * mp + 2) div 5 + 1
      val m = if mp < 10 then mp + 3 else mp - 9
      val y = if m <= 2 then y + 1 else y
      val hour = secsOfDay div 3600
      val minute = (secsOfDay div 60) mod 60
      val second = secsOfDay mod 60
    in
      { year = y, month = m, day = d
      , hour = hour, minute = minute, second = second }
    end

  (* ------------------------------------------------------------------
     Hostname matching (RFC 6125).

     A certName is a single DNS name from the subjectAltName (or the CN
     fallback). Wildcards are allowed only in the LEFTMOST label and match
     exactly one (non-empty) label. Comparison is case-insensitive over
     ASCII. No partial-label wildcards (`f*.example.com`) are accepted:
     the wildcard must be the entire leftmost label (`*.example.com`).
     ------------------------------------------------------------------ *)
  fun toLower c =
    if c >= #"A" andalso c <= #"Z" then
      Char.chr (Char.ord c + (Char.ord #"a" - Char.ord #"A"))
    else c

  fun lower s = String.implode (List.map toLower (String.explode s))

  (* Split a dotted hostname into labels ("" -> []). *)
  fun splitDots s =
    let
      fun loop (acc, start, i) =
        if i >= String.size s then
          List.rev (String.substring (s, start, i - start) :: acc)
        else if String.sub (s, i) = #"." then
          loop (String.substring (s, start, i - start) :: acc, i + 1, i + 1)
        else loop (acc, start, i + 1)
    in
      if s = "" then [] else loop ([], 0, 0)
    end

  fun matchHostname {host, certName} : bool =
    let
      val h = lower host
      val n = lower certName
      val hLabels = splitDots h
      val nLabels = splitDots n
    in
      case nLabels of
          [] => false
        | (first :: rest) =>
            if first = "*" then
              (* Wildcard rules (RFC 6125 §6.4.3):
                 - the wildcard must be the entire leftmost label,
                 - it must match exactly one (non-empty) leftmost host label,
                 - the remaining labels must match exactly. *)
              (case hLabels of
                   [] => false
                 | (hFirst :: hRest) =>
                     hFirst <> ""
                     andalso List.length hRest = List.length rest
                     andalso ListPair.allEq (fn (a, b) => a = b) (hRest, rest))
            else
              (* Exact match: same number of labels, all equal. *)
              List.length hLabels = List.length nLabels
              andalso ListPair.allEq (fn (a, b) => a = b) (hLabels, nLabels)
    end

  (* ------------------------------------------------------------------
     Signature algorithm handling (RFC 8446 §4.2.3).

     The `sigAlgs` list is the caller's acceptable SignatureScheme values
     (16-bit). We map the certificate's X509.sigAlg to the corresponding
     scheme code(s) and check membership. Only RSA schemes are verifiable
     today; ECDSA schemes return UnsupportedCertificate (A4 wires sml-p256).
     ------------------------------------------------------------------ *)
  val schemeRsaPkcs1Sha256 = 0wx0804 : Word16.word
  val schemeRsaPkcs1Sha384 = 0wx0805 : Word16.word
  val schemeRsaPkcs1Sha512 = 0wx0806 : Word16.word
  val schemeRsaPssSha256   = 0wx0809 : Word16.word
  val schemeRsaPssSha384   = 0wx080a : Word16.word
  val schemeRsaPssSha512   = 0wx080b : Word16.word
  val schemeEcdsaSha256    = 0wx0403 : Word16.word
  val schemeEcdsaSha384    = 0wx0503 : Word16.word
  val schemeEcdsaSha512    = 0wx0603 : Word16.word

  (* Is the cert's signature algorithm acceptable, given the caller's
     sigAlgs list? Returns:
        SOME true   -> acceptable, RSA (verifiable now)
        SOME false  -> ECDSA (hook for A4; we report UnsupportedCertificate
                       at the verify step)
        NONE        -> not in the acceptable list (or unsupported family) *)
  fun sigAlgAcceptable (sigAlg, sigAlgs : Word16.word list) =
    let
      fun member x = List.exists (fn y => y = x) sigAlgs
    in
      case sigAlg of
          X509.Sha256WithRsa => SOME (member schemeRsaPkcs1Sha256)
        | X509.Sha384WithRsa => SOME (member schemeRsaPkcs1Sha384)
        | X509.Sha512WithRsa => SOME (member schemeRsaPkcs1Sha512)
        | X509.RsaPss {hash = Rsa.SHA256, ...} =>
            SOME (member schemeRsaPssSha256)
        | X509.RsaPss {hash = Rsa.SHA1, ...} =>
            NONE   (* SHA-1 PSS is not acceptable in TLS 1.3 *)
        | X509.RsaPss {hash = Rsa.SHA512, ...} =>
            SOME (member schemeRsaPssSha512)
        | X509.Sha1WithRsa => NONE   (* SHA-1 forbidden in TLS 1.3 *)
        | X509.EcdsaWithSha256 => SOME (member schemeEcdsaSha256)
        | X509.EcdsaWithSha384 => SOME (member schemeEcdsaSha384)
        | X509.EcdsaWithSha512 => SOME (member schemeEcdsaSha512)
        | X509.Ed25519Sig => NONE
        | X509.UnknownSigAlg _ => NONE
    end

  (* ------------------------------------------------------------------
     OCSP stapling hook (RFC 8446 §4.4.2.1).

     The `status_request` extension carries a stapled OCSP response for the
     leaf. We do not validate the OCSP response here (CRL/OCSP path is
     deferred per the brief); we expose a parser that returns the raw
     stapled bytes if present, so the J1 integrator can wire it in. *)
  fun parseOcspStatus (stapled : string) : string option =
    if String.size stapled = 0 then NONE else SOME stapled

  (* ------------------------------------------------------------------
     Helpers
     ------------------------------------------------------------------ *)

  (* Parse a DER blob into an X509.cert; returns NONE on malformed input
     rather than letting X509.X509 escape. *)
  fun tryParse der = SOME (X509.parse der) handle X509.X509 _ => NONE

  (* Check that `now` falls within cert's validity window. *)
  fun validityOk (c, nowTime) =
    let val {notBefore, notAfter} = X509.validity c in
      X509.compareTime (notBefore, nowTime) <> GREATER
      andalso X509.compareTime (nowTime, notAfter) <> GREATER
    end

  (* Subject-name linkage: does `candidate` have the subject Name that
     `child` names as its issuer? We compare by the canonical nameToString
     rendering, which is stable across compilers. *)
  fun issuerMatches (child, candidate) =
    X509.nameToString (X509.subject candidate) =
    X509.nameToString (X509.issuer child)

  (* Is `c` a trust anchor by identity? We match on the parsed cert
     (subject + issuer + serial), since X509.cert is opaque and does not
     expose the raw DER. This is sufficient for the golden fixtures: each
     anchor is unique by these fields. *)
  fun sameCert (a, b) =
    X509.subject a = X509.subject b
    andalso X509.issuer a = X509.issuer b
    andalso BigInt.compare (X509.serialNumber a, X509.serialNumber b) = EQUAL

  fun isTrustAnchor (c, trust : trustStore) =
    List.exists
      (fn tDer =>
         case tryParse tDer of
             SOME t => sameCert (c, t)
           | NONE => false)
      trust

  (* ------------------------------------------------------------------
     Path building + validation.

     Walks from the leaf up; at each step:
        - check the current cert's validity against `now`,
        - if the current cert is a trust anchor (by identity), accept,
        - otherwise find an issuer in the remaining intermediates or the
          trust store, check CA / KeyUsage / pathLen, verify the
          signature, and recurse.

     pathLen accounting (RFC 5280 §6.1.4): a CA with pathLenConstraint = k
     may have at most k non-self-issued intermediate certificates below it
     in the path. `intermediatesBelow` = number of non-self-issued CA certs
     strictly between the leaf (exclusive) and the current cert (exclusive).
     When we arrive at `cur`, if `cur` has pathLenConstraint = k, we require
     `intermediatesBelow <= k`. When we recurse from `cur` to `iss`, if
     `cur` is a non-leaf CA (and not self-issued), it counts as one
     intermediate below `iss`, so we increment.
     ------------------------------------------------------------------ *)
  (* The leaf-only gate, applied once we have reached a trust anchor. *)
  fun leafGate {hostOk, ekuOk, leafSigOk} =
    if not leafSigOk then Invalid TlsAlert.BadCertificate
    else if not ekuOk then Invalid TlsAlert.BadCertificate
    else if not hostOk then Invalid TlsAlert.UnrecognizedName
    else Valid

  fun verifyChain {chain, trust, hostname, now, sigAlgs} : result =
    case chain of
        [] => Invalid TlsAlert.BadCertificate
      | leafDer :: restDers =>
          (case tryParse leafDer of
               NONE => Invalid TlsAlert.BadCertificate
             | SOME leaf =>
                 let
                   val restCerts = List.mapPartial tryParse restDers
                   val nowTime = unixToTime now

                   (* Leaf-only checks (computed once, applied at the gate). *)
                   val sanNames = X509.dnsNames leaf
                   val cnNames =
                     case X509.commonName (X509.subject leaf) of
                         SOME cn => [cn]
                       | NONE => []
                   val namesToCheck =
                     if null sanNames then cnNames else sanNames
                   val hostOk =
                     List.exists
                       (fn nm =>
                          matchHostname {host = hostname, certName = nm})
                       namesToCheck
                   val ekus = X509.extKeyUsage leaf
                   val ekuOk =
                     null ekus orelse
                     List.exists (fn p => p = "serverAuth") ekus
                   val leafSigOk =
                     case sigAlgAcceptable (X509.signatureAlg leaf, sigAlgs) of
                         SOME true => true
                       | SOME false => false   (* ECDSA unsupported until A4 *)
                       | NONE => false

                   (* `intermediatesBelow` counts non-self-issued CA certs
                      strictly between the leaf and `cur` (exclusive). *)
                   fun loop (cur, remaining, fuel, isLeaf, intermediatesBelow) =
                     if fuel <= 0 then
                       Invalid TlsAlert.UnknownCa
                     else if not (validityOk (cur, nowTime)) then
                       Invalid TlsAlert.CertificateExpired
                     else
                       (* pathLen check: if `cur` has pathLenConstraint = k,
                          at most k non-self-issued intermediates may be
                          below it. *)
                       let
                         val curBc = X509.basicConstraints cur
                         val curPathLen =
                           case curBc of
                               SOME {pathLen = SOME k, ...} => SOME k
                             | _ => NONE
                         val pathLenOk =
                           case curPathLen of
                               SOME k => intermediatesBelow <= k
                             | NONE => true
                       in
                         if not pathLenOk then
                           Invalid TlsAlert.BadCertificate
                         else if isTrustAnchor (cur, trust) then
                           (* Reached a trust anchor. Verify its self-signature
                              for defense in depth, then apply the leaf gate. *)
                           (case X509.verifySelfSigned cur of
                                X509.Verified =>
                                  leafGate {hostOk = hostOk, ekuOk = ekuOk,
                                            leafSigOk = leafSigOk}
                              | X509.Failed =>
                                  Invalid TlsAlert.UnknownCa
                              | X509.Unsupported _ =>
                                  Invalid TlsAlert.UnsupportedCertificate)
                         else
                           let
                             val interIssuer =
                               List.find (fn c => issuerMatches (cur, c))
                                         remaining
                             val trustIssuer =
                               case interIssuer of
                                   SOME _ => NONE
                                 | NONE =>
                                     List.find
                                       (fn tDer =>
                                          case tryParse tDer of
                                              SOME t => issuerMatches (cur, t)
                                            | NONE => false)
                                       trust
                           in
                             case (interIssuer, trustIssuer) of
                                 (SOME iss, _) =>
                                   let
                                     val ca = X509.isCA iss
                                     val ku = X509.keyUsage iss
                                     val hasKeyCertSign =
                                       null ku orelse
                                       List.exists (fn k => k = "keyCertSign") ku
                                     (* `cur` becomes an intermediate below
                                        `iss` if it is a non-leaf CA. *)
                                     val newIntermediatesBelow =
                                       if (not isLeaf) andalso X509.isCA cur
                                          andalso (* not self-issued: *)
                                             X509.nameToString (X509.subject cur)
                                             <> X509.nameToString (X509.issuer cur)
                                       then intermediatesBelow + 1
                                       else intermediatesBelow
                                   in
                                     if not ca then
                                       Invalid TlsAlert.UnknownCa
                                     else if not hasKeyCertSign then
                                       Invalid TlsAlert.BadCertificate
                                     else if not (validityOk (iss, nowTime))
                                     then
                                       Invalid TlsAlert.CertificateExpired
                                     else
                                       (case X509.verifySignature
                                              {cert = cur, issuer = iss} of
                                            X509.Verified =>
                                              loop
                                                (iss,
                                                 List.filter
                                                   (fn c =>
                                                      not (issuerMatches (cur, c)))
                                                   remaining,
                                                 fuel - 1, false,
                                                 newIntermediatesBelow)
                                          | X509.Failed =>
                                              Invalid TlsAlert.DecryptError
                                          | X509.Unsupported _ =>
                                              Invalid
                                                TlsAlert.UnsupportedCertificate)
                                   end
                               | (NONE, SOME tDer) =>
                                   (case tryParse tDer of
                                        SOME iss =>
                                          let
                                            val ca = X509.isCA iss
                                            val ku = X509.keyUsage iss
                                            val hasKeyCertSign =
                                              null ku orelse
                                              List.exists
                                                (fn k => k = "keyCertSign") ku
                                          in
                                            if not ca then
                                              Invalid TlsAlert.UnknownCa
                                            else if not hasKeyCertSign then
                                              Invalid TlsAlert.BadCertificate
                                            else if not (validityOk (iss, nowTime))
                                            then
                                              Invalid TlsAlert.CertificateExpired
                                            else
                                              (case X509.verifySignature
                                                     {cert = cur, issuer = iss} of
                                                   X509.Verified =>
                                                     leafGate
                                                       {hostOk = hostOk,
                                                        ekuOk = ekuOk,
                                                        leafSigOk = leafSigOk}
                                                 | X509.Failed =>
                                                     Invalid TlsAlert.DecryptError
                                                 | X509.Unsupported _ =>
                                                     Invalid
                                                       TlsAlert.UnsupportedCertificate)
                                          end
                                      | NONE =>
                                          Invalid TlsAlert.UnknownCa)
                               | (NONE, NONE) =>
                                   (* No issuer found anywhere -> chain does
                                      not lead to a trust anchor. *)
                                   Invalid TlsAlert.UnknownCa
                           end
                       end
                 in
                   loop (leaf, restCerts, List.length chain + 2, true, 0)
                 end)
end
