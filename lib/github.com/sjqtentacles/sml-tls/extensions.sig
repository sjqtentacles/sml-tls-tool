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
     CH carries a list; SH carries a single selected entry; the
     HelloRetryRequest form carries only the server's `selected_group`
     (2 bytes, no key). *)
  val encodeKeyShareCH : keyShareEntry list -> string
  val decodeKeyShareCH : string -> keyShareEntry list option
  val encodeKeyShareSH : keyShareEntry -> string
  val decodeKeyShareSH : string -> keyShareEntry option
  (* HRR key_share body: just the 2-byte selected_group (§4.1.4). *)
  val encodeKeyShareHRR : Word16.word -> string
  val decodeKeyShareHRR : string -> Word16.word option

  (* ---- cookie (§4.2.2) ----
     A single opaque<1..2^16-1>: a 2-byte length prefix then the bytes.
     The server may send a cookie in a HelloRetryRequest; the client
     echoes it verbatim in ClientHello2. *)
  val encodeCookie : string -> string
  val decodeCookie : string -> string option

  (* ---- psk_key_exchange_modes (§4.2.9) ----
     1-byte list length then 1-byte modes (0 = psk_ke, 1 = psk_dhe_ke). *)
  val pskModeKe    : Word8.word   (* 0 *)
  val pskModeDheKe : Word8.word   (* 1 *)
  val encodePskKeyExchangeModes : Word8.word list -> string
  val decodePskKeyExchangeModes : string -> Word8.word list option

  (* ---- early_data (§4.2.10) ----
     Empty body in ClientHello/EncryptedExtensions; a uint32
     max_early_data_size in a NewSessionTicket. *)
  val encodeEarlyDataEmpty : string                       (* "" *)
  val encodeEarlyDataMaxSize : Word32.word -> string
  val decodeEarlyDataMaxSize : string -> Word32.word option

  (* ---- pre_shared_key (§4.2.11) ----
     A PSK identity: the opaque ticket bytes plus the obfuscated ticket
     age (uint32). *)
  type pskIdentity = {identity : string, obfuscatedTicketAge : Word32.word}
  (* The ClientHello body WITHOUT the binders, plus the binder list,
     encoded separately so the binder MAC can be computed over the
     partial transcript (the ClientHello up to and including the
     identities, §4.2.11.2). `encodeOfferedPsksHead` is identities +
     the 2-byte binders-list-length prefix only; `binderListBody` is the
     concatenated 1-byte-prefixed binder entries (without the outer
     2-byte length). The full extension data is head ^ binderListBody. *)
  val encodeOfferedPsksIdentities : pskIdentity list -> string
  val binderListLength : string list -> int
  val encodeBinderList : string list -> string
  (* SH form: the 2-byte selected_identity index. *)
  val encodeSelectedIdentity : Word16.word -> string
  val decodeSelectedIdentity : string -> Word16.word option
  (* Decode an OfferedPsks body into (identities, binders). *)
  val decodeOfferedPsks : string -> (pskIdentity list * string list) option

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
