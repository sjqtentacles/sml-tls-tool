(* extensions.sml

   Stub implementation of TLS_EXTENSIONS (Track A3, Phase 2 parallel half).

   Every function raises `Fail "todo: A3"`. The Phase 0 interface freeze
   only requires the tree to compile against the frozen contract; the
   A3 subagent replaces each body with RFC 8448-extension-block-driven code. *)

structure TlsExtensions :> TLS_EXTENSIONS =
struct
  type keyShareEntry = {group : Word16.word, keyExchange : string}

  fun encodeKeyShareCH (xs : keyShareEntry list) : string =
    raise Fail "todo: A3"

  fun decodeKeyShareCH (s : string) : keyShareEntry list option =
    raise Fail "todo: A3"

  fun encodeKeyShareSH (e : keyShareEntry) : string =
    raise Fail "todo: A3"

  fun decodeKeyShareSH (s : string) : keyShareEntry option =
    raise Fail "todo: A3"

  fun encodeSupportedVersionsCH (vs : Word16.word list) : string =
    raise Fail "todo: A3"

  fun decodeSelectedVersionSH (s : string) : Word16.word option =
    raise Fail "todo: A3"

  fun encodeSupportedGroups (vs : Word16.word list) : string =
    raise Fail "todo: A3"

  fun decodeSupportedGroups (s : string) : Word16.word list option =
    raise Fail "todo: A3"

  fun encodeSignatureAlgorithms (vs : Word16.word list) : string =
    raise Fail "todo: A3"

  fun decodeSignatureAlgorithms (s : string) : Word16.word list option =
    raise Fail "todo: A3"

  fun encodeServerName (s : string) : string =
    raise Fail "todo: A3"

  fun decodeServerName (s : string) : string option =
    raise Fail "todo: A3"

  fun encodeAlpn (xs : string list) : string =
    raise Fail "todo: A3"

  fun decodeAlpn (s : string) : string list option =
    raise Fail "todo: A3"

  fun negotiateVersion (vs : Word16.word list) : Word16.word option =
    raise Fail "todo: A3"

  fun negotiateGroup {clientShares, serverGroups} : Word16.word option =
    raise Fail "todo: A3"

  fun negotiateSigAlg {client, server} : Word16.word option =
    raise Fail "todo: A3"

  (* Phase 0 placeholders: the A3 subagent replaces these with the real
     8-byte sentinels. Empty string keeps the structure loadable while
     bodies are stubbed; `raise Fail` would abort at elaboration time. *)
  val downgradeSentinelTls12 : string = ""
  val downgradeSentinelTls11 : string = ""
end
