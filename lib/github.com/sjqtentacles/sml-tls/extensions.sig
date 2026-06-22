(* extensions.sig

   Pure parse/build of every TLS 1.3 extension body the handshake needs,
   plus stateless negotiation helpers (RFC 8446 §4.2). No state-machine
   edits: this module knows nothing about `TlsClient`/`TlsServer`.

   This is the frozen contract for Track A3 (Phase 2, parallel half).
   The Phase 0 stub raises `Fail "todo: A3"` from every function; the
   A3 subagent fills in the bodies against RFC 8448 extension blocks. *)

signature TLS_EXTENSIONS =
sig
  (* A `key_share` entry: a named group plus that group's key exchange
     bytes. Group codes are the `TlsHandshake.groupX25519` / future
     `groupSecp256r1` constants. *)
  type keyShareEntry = {group : Word16.word, keyExchange : string}

  (* ---- key_share (§4.2.8) ----
     CH carries a list; SH/HRR carry a single selected entry. *)
  val encodeKeyShareCH : keyShareEntry list -> string
  val decodeKeyShareCH : string -> keyShareEntry list option
  val encodeKeyShareSH : keyShareEntry -> string
  val decodeKeyShareSH : string -> keyShareEntry option

  (* ---- supported_versions (§4.2.1) ----
     CH carries a list; SH carries a single selected version. *)
  val encodeSupportedVersionsCH : Word16.word list -> string
  val decodeSelectedVersionSH   : string -> Word16.word option

  (* ---- supported_groups (§4.2.7) ---- *)
  val encodeSupportedGroups : Word16.word list -> string
  val decodeSupportedGroups : string -> Word16.word list option

  (* ---- signature_algorithms (§4.2.3) ---- *)
  val encodeSignatureAlgorithms : Word16.word list -> string
  val decodeSignatureAlgorithms : string -> Word16.word list option

  (* ---- server_name / SNI (RFC 6066, host_name form) ---- *)
  val encodeServerName : string -> string
  val decodeServerName : string -> string option

  (* ---- ALPN (RFC 7301) ---- *)
  val encodeAlpn : string list -> string
  val decodeAlpn : string -> string list option

  (* ---- Stateless negotiation helpers ----
     Each returns the selected value, or NONE when the intersection is
     empty (caller maps to the appropriate alert). *)
  val negotiateVersion : Word16.word list -> Word16.word option
  val negotiateGroup   : {clientShares  : keyShareEntry list,
                          serverGroups  : Word16.word list} -> Word16.word option
  val negotiateSigAlg  : {client : Word16.word list,
                          server : Word16.word list} -> Word16.word option

  (* ---- Downgrade-protection sentinels (§4.1.3) ----
     The last 8 bytes of the ServerHello.random that a TLS 1.2 / 1.1
     server would set; a TLS 1.3 client MUST abort if it sees them. *)
  val downgradeSentinelTls12 : string
  val downgradeSentinelTls11 : string
end
