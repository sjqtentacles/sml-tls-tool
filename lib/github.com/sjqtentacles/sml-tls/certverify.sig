(* certverify.sig

   Certificate-chain validation for TLS 1.3 (RFC 8446 §4.4.2), built on
   sml-x509 + sml-rsa (+ sml-p256 ECDSA, wired at J1).

   Pure and deterministic: the trust store, hostname, current time, and
   acceptable signature algorithms are all passed in as parameters, so
   the same inputs always produce the same accept/alert outcome on both
   MLton and Poly/ML. No network access at test time.

   This is the frozen contract for Track A2 (Phase 3). The Phase 0 stub
   raises `Fail "todo: A2"` from every function; the A2 subagent fills
   in the bodies against golden-chain fixtures. *)

signature TLS_CERT_VERIFY =
sig
  (* DER-encoded trust anchors (one string per anchor certificate). *)
  type trustStore = string list

  (* The outcome of chain validation. `Invalid` carries the alert the
     caller should send (and that the J1 integrator wires into the
     handshake state machine). *)
  datatype result = Valid | Invalid of TlsAlert.alertDescription

  (* Validate a leaf-first DER certificate chain to a trust anchor:
       - chain building to a caller-supplied trust store,
       - signature verification up the chain (RSA-PSS/PKCS1; ECDSA via
         A4 `sml-p256` once wired, otherwise `Invalid UnsupportedCertificate`),
       - validity dates against the injected `now`,
       - hostname/SAN matching incl. wildcard rules (RFC 6125),
       - KeyUsage / EKU / BasicConstraints / pathLenConstraint (RFC 5280),
       - `sigAlgs` enforcement (§4.2.3). *)
  val verifyChain : {chain    : string list,      (* leaf-first DER       *)
                     trust    : trustStore,
                     hostname : string,
                     now      : int,              (* injected unix time   *)
                     sigAlgs  : Word16.word list} -> result

  (* RFC 6125 hostname / SAN matching, including wildcard rules:
       `*.a.com` matches `x.a.com`, not `a.com`, not `x.y.a.com`. *)
  val matchHostname : {host : string, certName : string} -> bool
end
