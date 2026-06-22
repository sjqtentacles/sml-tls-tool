(* recordprotect.sml

   Stub implementation of TLS_RECORD_PROTECT (Track A1, Phase 1).

   Every function raises `Fail "todo: A1"`. The Phase 0 interface freeze
   only requires the tree to compile against the frozen contract; the
   A1 subagent replaces each body with the RFC 8446/8448-correct code. *)

structure TlsRecordProtect :> TLS_RECORD_PROTECT =
struct
  type state = {key : string, iv : string, seq : int}

  fun init {key, iv} : state =
    raise Fail "todo: A1"

  fun nonce {iv, seq} : string =
    raise Fail "todo: A1"

  val maxPlaintext : int = 16384   (* 2^14, RFC 8446 §5.1 *)

  fun protect {state, innerType, plaintext, pad} : string * state =
    raise Fail "todo: A1"

  fun unprotect {state, record}
      : (TlsRecord.contentType * string * state) option =
    raise Fail "todo: A1"
end
