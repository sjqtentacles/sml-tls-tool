(* certverify.sml

   Stub implementation of TLS_CERT_VERIFY (Track A2, Phase 3).

   Every function raises `Fail "todo: A2"`. The Phase 0 interface freeze
   only requires the tree to compile against the frozen contract; the
   A2 subagent replaces each body with golden-chain-fixture-driven code. *)

structure TlsCertVerify :> TLS_CERT_VERIFY =
struct
  type trustStore = string list

  datatype result = Valid | Invalid of TlsAlert.alertDescription

  fun verifyChain {chain, trust, hostname, now, sigAlgs} : result =
    raise Fail "todo: A2"

  fun matchHostname {host, certName} : bool =
    raise Fail "todo: A2"
end
