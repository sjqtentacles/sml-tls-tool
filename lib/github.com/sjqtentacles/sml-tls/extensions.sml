(* extensions.sml

   Implementation of TLS_EXTENSIONS (Track A3, Phase 2 parallel half).

   Pure parse/build of every TLS 1.3 extension body the handshake needs,
   plus stateless negotiation helpers. No state-machine edits: this module
   knows nothing about `TlsClient`/`TlsServer`.

   Wire format references:
     - key_share CH:        RFC 8446 §4.2.8 -- 2-byte list len, then entries
                            {2-byte group, 2-byte klen, key}.
     - key_share SH/HRR:    RFC 8446 §4.2.8 -- a single entry, no list prefix.
     - supported_versions CH: 1-byte list len, then 2-byte versions.
     - supported_versions SH: 2-byte selected version, no length prefix.
     - supported_groups:    2-byte list len, then 2-byte named groups.
     - signature_algorithms: 2-byte list len, then 2-byte schemes.
     - server_name (SNI):   RFC 6066 -- 2-byte list len, then
                            {1-byte name_type, 2-byte name len, name}.
                            Only host_name (type 0) is supported.
     - ALPN:                RFC 7301 -- 2-byte list len, then
                            {1-byte proto len, proto}*.

   All decoders are total: malformed input -> NONE, never raises. *)

structure TlsExtensions :> TLS_EXTENSIONS =
struct
  type keyShareEntry = {group : Word16.word, keyExchange : string}

  (* ---- shared helpers ----
     The wire encoding is the same one `TlsHandshake` uses; we re-derive
     it here rather than depending on the (opaque) TlsHandshake structure
     so this module stays a pure leaf in the codec DAG. *)
  fun word16ToBytes w =
    String.implode [
      Byte.byteToChar (Word8.fromLarge (Word16.toLarge (Word16.>> (w, 0w8)))),
      Byte.byteToChar (Word8.fromLarge (Word16.toLarge (Word16.andb (w, 0wxFF))))
    ]

  fun bytesToWord16 (hi, lo) =
    Word16.orb (Word16.<< (Word16.fromLarge (Word8.toLarge hi), 0w8),
                Word16.fromLarge (Word8.toLarge lo))

  fun byteAt (s, i) =
    if i < 0 orelse i >= String.size s then NONE
    else SOME (Byte.charToByte (String.sub (s, i)))

  (* Read a big-endian 16-bit length prefix at offset i; returns
     (length, nextOffset) or NONE if truncated. *)
  fun readU16 (s, i) =
    case (byteAt (s, i), byteAt (s, i + 1)) of
        (SOME hi, SOME lo) => SOME (Word16.toInt (bytesToWord16 (hi, lo)),
                                    i + 2)
      | _ => NONE

  fun substringOpt (s, start, len) =
    if start < 0 orelse len < 0 orelse start + len > String.size s then NONE
    else SOME (String.substring (s, start, len))

  (* =================================================================== *)
  (* key_share (§4.2.8)                                                   *)
  (* =================================================================== *)

  (* CH form: 2-byte list length, then entries {group:16, klen:16, key}. *)
  fun encodeKeyShareCH (xs : keyShareEntry list) : string =
    let
      fun one {group, keyExchange} =
        word16ToBytes group
        ^ word16ToBytes (Word16.fromInt (String.size keyExchange))
        ^ keyExchange
      val body = String.concat (List.map one xs)
    in
      word16ToBytes (Word16.fromInt (String.size body)) ^ body
    end

  fun decodeKeyShareCH (s : string) : keyShareEntry list option =
    let
      (* Loop over entries starting at offset `i`, stopping at `end0`. *)
      fun loop (i, end0, acc) =
        if i = end0 then SOME (List.rev acc)
        else if i + 4 > end0 then NONE
        else
          case (byteAt (s, i), byteAt (s, i + 1)) of
              (SOME hi, SOME lo) =>
                let val group = bytesToWord16 (hi, lo) in
                  case readU16 (s, i + 2) of
                      NONE => NONE
                    | SOME (klen, j) =>
                        if j + klen > end0 then NONE
                        else
                          case substringOpt (s, j, klen) of
                              NONE => NONE
                            | SOME keyExchange =>
                                if klen = 0 then NONE  (* zero-length key *)
                                else loop (j + klen, end0,
                                           {group = group,
                                            keyExchange = keyExchange} :: acc)
                end
            | _ => NONE
    in
      case readU16 (s, 0) of
          NONE => NONE  (* includes empty input *)
        | SOME (listLen, start) =>
            if start + listLen <> String.size s then NONE  (* trailing junk *)
            else if listLen = 0 then SOME []  (* empty list is well-formed *)
            else loop (start, start + listLen, [])
    end

  (* HRR form: just the 2-byte selected_group (§4.1.4 / §4.2.8). *)
  fun encodeKeyShareHRR (group : Word16.word) : string =
    word16ToBytes group

  fun decodeKeyShareHRR (s : string) : Word16.word option =
    if String.size s <> 2 then NONE
    else case (byteAt (s, 0), byteAt (s, 1)) of
             (SOME hi, SOME lo) => SOME (bytesToWord16 (hi, lo))
           | _ => NONE

  (* SH form: a single entry {group:16, klen:16, key}, no list prefix. *)
  fun encodeKeyShareSH (e : keyShareEntry) : string =
    word16ToBytes (#group e)
    ^ word16ToBytes (Word16.fromInt (String.size (#keyExchange e)))
    ^ (#keyExchange e)

  fun decodeKeyShareSH (s : string) : keyShareEntry option =
    if String.size s < 4 then NONE
    else
      let
        val group = bytesToWord16
          (valOf (byteAt (s, 0)), valOf (byteAt (s, 1)))
              handle Option => raise Fail "decodeKeyShareSH: unreachable"
      in
        case readU16 (s, 2) of
            NONE => NONE
          | SOME (klen, keyStart) =>
              if klen = 0 then NONE  (* zero-length key *)
              else if keyStart + klen <> String.size s then NONE
              else case substringOpt (s, keyStart, klen) of
                       NONE => NONE
                     | SOME keyExchange =>
                         SOME {group = group, keyExchange = keyExchange}
      end

  (* =================================================================== *)
  (* supported_versions (§4.2.1)                                          *)
  (* =================================================================== *)

  (* CH form: 1-byte list length, then 2-byte versions. *)
  fun encodeSupportedVersionsCH (vs : Word16.word list) : string =
    let
      val body = String.concat (List.map word16ToBytes vs)
      val n = String.size body
    in
      if n > 255 then raise Fail "supported_versions: too many"
      else String.str (Char.chr n) ^ body
    end

  (* SH form: just the 2-byte selected version, no length prefix. *)
  fun decodeSelectedVersionSH (s : string) : Word16.word option =
    if String.size s <> 2 then NONE
    else case (byteAt (s, 0), byteAt (s, 1)) of
             (SOME hi, SOME lo) => SOME (bytesToWord16 (hi, lo))
           | _ => NONE

  (* =================================================================== *)
  (* supported_groups (§4.2.7)                                            *)
  (* =================================================================== *)

  fun encodeSupportedGroups (vs : Word16.word list) : string =
    let
      val body = String.concat (List.map word16ToBytes vs)
    in
      word16ToBytes (Word16.fromInt (String.size body)) ^ body
    end

  fun decodeSupportedGroups (s : string) : Word16.word list option =
    case readU16 (s, 0) of
        NONE => NONE
      | SOME (listLen, start) =>
          if start + listLen <> String.size s then NONE
          else if listLen mod 2 <> 0 then NONE  (* odd-length list *)
          else
            let
              fun loop (i, end0, acc) =
                if i = end0 then SOME (List.rev acc)
                else
                  case (byteAt (s, i), byteAt (s, i + 1)) of
                       (SOME hi, SOME lo) =>
                         loop (i + 2, end0, bytesToWord16 (hi, lo) :: acc)
                     | _ => NONE
            in
              loop (start, start + listLen, [])
            end

  (* =================================================================== *)
  (* signature_algorithms (§4.2.3)                                        *)
  (* =================================================================== *)

  fun encodeSignatureAlgorithms (vs : Word16.word list) : string =
    let
      val body = String.concat (List.map word16ToBytes vs)
    in
      word16ToBytes (Word16.fromInt (String.size body)) ^ body
    end

  fun decodeSignatureAlgorithms (s : string) : Word16.word list option =
    case readU16 (s, 0) of
        NONE => NONE
      | SOME (listLen, start) =>
          if start + listLen <> String.size s then NONE
          else if listLen mod 2 <> 0 then NONE
          else
            let
              fun loop (i, end0, acc) =
                if i = end0 then SOME (List.rev acc)
                else
                  case (byteAt (s, i), byteAt (s, i + 1)) of
                       (SOME hi, SOME lo) =>
                         loop (i + 2, end0, bytesToWord16 (hi, lo) :: acc)
                     | _ => NONE
            in
              loop (start, start + listLen, [])
            end

  (* =================================================================== *)
  (* server_name / SNI (RFC 6066, host_name form)                         *)
  (* =================================================================== *)

  (* ServerNameList: 2-byte list length, then ServerName entries.
     A ServerName is {name_type:1, HostName: {2-byte len, name}}.
     We only support name_type 0 (host_name) and encode exactly one entry. *)
  fun encodeServerName (name : string) : string =
    let
      val nameLen = String.size name
      val entry = String.str (Char.chr 0)  (* name_type = host_name *)
                  ^ word16ToBytes (Word16.fromInt nameLen)
                  ^ name
      val listLen = String.size entry
    in
      word16ToBytes (Word16.fromInt listLen) ^ entry
    end

  fun decodeServerName (s : string) : string option =
    case readU16 (s, 0) of
        NONE => NONE
      | SOME (listLen, start) =>
          if start + listLen <> String.size s then NONE
          else if listLen = 0 then NONE
          else
            (* Parse a single host_name entry; reject any non-host_name
               name_type or a multi-entry list (the handshake only ever
               carries one SNI name). *)
            case byteAt (s, start) of
                NONE => NONE
              | SOME nameType =>
                  if nameType <> 0w0 then NONE  (* only host_name supported *)
                  else
                    case readU16 (s, start + 1) of
                        NONE => NONE
                      | SOME (nameLen, nameStart) =>
                          if nameStart + nameLen <> start + listLen then NONE
                          else case substringOpt (s, nameStart, nameLen) of
                                   NONE => NONE
                                 | SOME name => SOME name

  (* =================================================================== *)
  (* ALPN (RFC 7301)                                                      *)
  (* =================================================================== *)

  (* ProtocolNameList: 2-byte list length, then ProtocolName entries,
     each {1-byte length, opaque<1..255>}. *)
  fun encodeAlpn (xs : string list) : string =
    let
      fun one p =
        let val n = String.size p in
          if n > 255 then raise Fail "alpn: protocol too long"
          else String.str (Char.chr n) ^ p
        end
      val body = String.concat (List.map one xs)
    in
      word16ToBytes (Word16.fromInt (String.size body)) ^ body
    end

  fun decodeAlpn (s : string) : string list option =
    case readU16 (s, 0) of
        NONE => NONE
      | SOME (listLen, start) =>
          if start + listLen <> String.size s then NONE
          else
            let
              fun loop (i, end0, acc) =
                if i = end0 then SOME (List.rev acc)
                else
                  case byteAt (s, i) of
                      NONE => NONE
                    | SOME plenB =>
                        let val plen = Word8.toInt plenB in
                          if plen = 0 then NONE  (* zero-length protocol *)
                          else if i + 1 + plen > end0 then NONE
                          else case substringOpt (s, i + 1, plen) of
                                   NONE => NONE
                                 | SOME p => loop (i + 1 + plen, end0, p :: acc)
                        end
            in
              loop (start, start + listLen, [])
            end

  (* =================================================================== *)
  (* cookie (§4.2.2)                                                      *)
  (* =================================================================== *)

  fun encodeCookie (cookie : string) : string =
    word16ToBytes (Word16.fromInt (String.size cookie)) ^ cookie

  fun decodeCookie (s : string) : string option =
    case readU16 (s, 0) of
        NONE => NONE
      | SOME (n, start) =>
          if n = 0 then NONE  (* cookie<1..2^16-1>: non-empty *)
          else if start + n <> String.size s then NONE
          else substringOpt (s, start, n)

  (* =================================================================== *)
  (* psk_key_exchange_modes (§4.2.9)                                      *)
  (* =================================================================== *)

  val pskModeKe    : Word8.word = 0w0
  val pskModeDheKe : Word8.word = 0w1

  fun encodePskKeyExchangeModes (modes : Word8.word list) : string =
    let val body = String.implode (List.map Byte.byteToChar modes) in
      String.str (Char.chr (String.size body)) ^ body
    end

  fun decodePskKeyExchangeModes (s : string) : Word8.word list option =
    case byteAt (s, 0) of
        NONE => NONE
      | SOME lenB =>
          let val n = Word8.toInt lenB in
            if n = 0 then NONE
            else if 1 + n <> String.size s then NONE
            else
              let
                fun loop (i, acc) =
                  if i = 1 + n then SOME (List.rev acc)
                  else case byteAt (s, i) of
                           NONE => NONE
                         | SOME b => loop (i + 1, b :: acc)
              in loop (1, []) end
          end

  (* =================================================================== *)
  (* early_data (§4.2.10)                                                 *)
  (* =================================================================== *)

  fun word32ToBytes (w : Word32.word) : string =
    String.implode [
      Byte.byteToChar (Word8.fromLarge (Word32.toLarge (Word32.>> (w, 0w24)))),
      Byte.byteToChar (Word8.fromLarge (Word32.toLarge (Word32.>> (w, 0w16)))),
      Byte.byteToChar (Word8.fromLarge (Word32.toLarge (Word32.>> (w, 0w8)))),
      Byte.byteToChar (Word8.fromLarge (Word32.toLarge (Word32.andb (w, 0wxFF))))
    ]

  fun bytesToWord32 (a, b, c, d) =
    Word32.orb (Word32.<< (Word32.fromLarge (Word8.toLarge a), 0w24),
    Word32.orb (Word32.<< (Word32.fromLarge (Word8.toLarge b), 0w16),
    Word32.orb (Word32.<< (Word32.fromLarge (Word8.toLarge c), 0w8),
                Word32.fromLarge (Word8.toLarge d))))

  val encodeEarlyDataEmpty : string = ""

  fun encodeEarlyDataMaxSize (w : Word32.word) : string = word32ToBytes w

  fun decodeEarlyDataMaxSize (s : string) : Word32.word option =
    if String.size s <> 4 then NONE
    else case (byteAt (s, 0), byteAt (s, 1), byteAt (s, 2), byteAt (s, 3)) of
             (SOME a, SOME b, SOME c, SOME d) =>
               SOME (bytesToWord32 (a, b, c, d))
           | _ => NONE

  (* =================================================================== *)
  (* pre_shared_key (§4.2.11)                                             *)
  (* =================================================================== *)

  type pskIdentity = {identity : string, obfuscatedTicketAge : Word32.word}

  (* identities: 2-byte total length, then entries
       {opaque identity<1..2^16-1> (2-byte len + bytes), uint32 age}. *)
  fun encodeOfferedPsksIdentities (ids : pskIdentity list) : string =
    let
      fun one {identity, obfuscatedTicketAge} =
        word16ToBytes (Word16.fromInt (String.size identity)) ^ identity
        ^ word32ToBytes obfuscatedTicketAge
      val body = String.concat (List.map one ids)
    in
      word16ToBytes (Word16.fromInt (String.size body)) ^ body
    end

  (* The on-the-wire length of the binder list body (each binder is a
     1-byte length prefix + the binder bytes). *)
  fun binderListLength (binders : string list) : int =
    List.foldl (fn (b, n) => n + 1 + String.size b) 0 binders

  (* The binder list: 2-byte total length, then 1-byte-prefixed entries. *)
  fun encodeBinderList (binders : string list) : string =
    let
      val body = String.concat
        (List.map (fn b => String.str (Char.chr (String.size b)) ^ b) binders)
    in
      word16ToBytes (Word16.fromInt (String.size body)) ^ body
    end

  fun encodeSelectedIdentity (idx : Word16.word) : string =
    word16ToBytes idx

  fun decodeSelectedIdentity (s : string) : Word16.word option =
    if String.size s <> 2 then NONE
    else case (byteAt (s, 0), byteAt (s, 1)) of
             (SOME hi, SOME lo) => SOME (bytesToWord16 (hi, lo))
           | _ => NONE

  fun decodeOfferedPsks (s : string)
      : (pskIdentity list * string list) option =
    case readU16 (s, 0) of
        NONE => NONE
      | SOME (idsLen, idsStart) =>
          if idsStart + idsLen > String.size s then NONE
          else
            let
              val idsEnd = idsStart + idsLen
              fun readIds (i, acc) =
                if i = idsEnd then SOME (List.rev acc)
                else case readU16 (s, i) of
                         NONE => NONE
                       | SOME (ilen, istart) =>
                           if ilen = 0 orelse istart + ilen + 4 > idsEnd then NONE
                           else
                             (case (substringOpt (s, istart, ilen),
                                    byteAt (s, istart + ilen),
                                    byteAt (s, istart + ilen + 1),
                                    byteAt (s, istart + ilen + 2),
                                    byteAt (s, istart + ilen + 3)) of
                                  (SOME idy, SOME a, SOME b, SOME c, SOME d) =>
                                    readIds (istart + ilen + 4,
                                      {identity = idy,
                                       obfuscatedTicketAge =
                                         bytesToWord32 (a, b, c, d)} :: acc)
                                | _ => NONE)
            in
              case readIds (idsStart, []) of
                  NONE => NONE
                | SOME ids =>
                    (case readU16 (s, idsEnd) of
                         NONE => NONE
                       | SOME (bLen, bStart) =>
                           if bStart + bLen <> String.size s then NONE
                           else
                             let
                               val bEnd = bStart + bLen
                               fun readBinders (i, acc) =
                                 if i = bEnd then SOME (List.rev acc)
                                 else case byteAt (s, i) of
                                          NONE => NONE
                                        | SOME lenB =>
                                            let val bl = Word8.toInt lenB in
                                              if bl = 0 orelse i + 1 + bl > bEnd then NONE
                                              else case substringOpt (s, i + 1, bl) of
                                                       NONE => NONE
                                                     | SOME bd =>
                                                         readBinders (i + 1 + bl, bd :: acc)
                                            end
                             in
                               case readBinders (bStart, []) of
                                   NONE => NONE
                                 | SOME binders => SOME (ids, binders)
                             end)
            end

  (* =================================================================== *)
  (* Stateless negotiation helpers                                       *)
  (* =================================================================== *)

  (* Server policy is fixed: TLS 1.3 only (0x0304). Return SOME 0x0304 iff
     the client offers it; otherwise NONE. The first 0x0304 in the client
     list wins (client preference order). *)
  val tls13 : Word16.word = 0wx0304

  fun negotiateVersion (clientVersions : Word16.word list)
      : Word16.word option =
    case List.find (fn v => v = tls13) clientVersions of
        SOME _ => SOME tls13
      | NONE => NONE

  (* negotiateGroup: walk the client's key_share entries in client-preference
     order; return the first group that also appears in the server's
     supported-groups list. *)
  fun negotiateGroup {clientShares, serverGroups} : Word16.word option =
    let
      fun member (g, gs) = List.exists (fn g' => g' = g) gs
      fun loop [] = NONE
        | loop ({group = g, keyExchange = _} :: rest) =
            if member (g, serverGroups) then SOME g
            else loop rest
    in
      loop clientShares
    end

  (* negotiateSigAlg: first client-preferred scheme the server also offers. *)
  fun negotiateSigAlg {client, server} : Word16.word option =
    let
      fun member (g, gs) = List.exists (fn g' => g' = g) gs
      fun loop [] = NONE
        | loop (x :: rest) =
            if member (x, server) then SOME x else loop rest
    in
      loop client
    end

  (* =================================================================== *)
  (* Downgrade-protection sentinels (§4.1.3)                             *)
  (* =================================================================== *)

  (* The last 8 bytes of ServerHello.random that a TLS 1.2 / 1.1 server
     sets to signal the negotiated version. A TLS 1.3 client MUST abort
     if it sees these in a ServerHello.random.

       TLS 1.2 sentinel:  44 4F 57 4E 47 52 44 01  ("DOWNGRD" ^ 0x01)
       TLS 1.1 sentinel:  44 4F 57 4E 47 52 44 00  ("DOWNGRD" ^ 0x00) *)
  val downgradeSentinelTls12 : string =
    String.implode [
      Char.chr 0x44, Char.chr 0x4F, Char.chr 0x57, Char.chr 0x4E,
      Char.chr 0x47, Char.chr 0x52, Char.chr 0x44, Char.chr 0x01
    ]
  val downgradeSentinelTls11 : string =
    String.implode [
      Char.chr 0x44, Char.chr 0x4F, Char.chr 0x57, Char.chr 0x4E,
      Char.chr 0x47, Char.chr 0x52, Char.chr 0x44, Char.chr 0x00
    ]
end
