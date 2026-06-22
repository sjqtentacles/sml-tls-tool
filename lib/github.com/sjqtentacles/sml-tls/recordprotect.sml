(* recordprotect.sml

   Implementation of TLS_RECORD_PROTECT (Track A1, Phase 1).

   Moves AEAD record encryption/decryption into the library so the state
   machine owns sequence numbers and nonces. Implements RFC 8446 §5.2
   (TLSInnerPlaintext + padding + content-type hiding) and §5.3
   (per-record nonce = static IV XOR big-endian seq, left-padded to
   nonceLen), with the 2^14 plaintext limit and `record_overflow`
   rejection from §5.1.

   The AEAD algorithm is inferred from the traffic-key length: a 16-byte
   key selects AES-128-GCM, a 32-byte key selects AES-256-GCM. (Both
   use a 12-byte nonce, so the nonce derivation is identical.) This
   covers the RFC 8448 vectors, which use AES-128-GCM. The J1
   integrator can refine the algorithm selection when wiring
   cipher-suite-specific traffic keys into the state machine. *)

structure TlsRecordProtect :> TLS_RECORD_PROTECT =
struct
  (* Opaque per-direction state: the traffic key, the static IV, the
     AEAD algorithm (inferred from the key length), and the
     monotonically-increasing 64-bit sequence counter. *)
  type state = {key : string, iv : string, alg : Aead.alg, seq : int}

  (* Infer the AEAD algorithm from the traffic-key length. 16 bytes ->
     AES-128-GCM, 32 bytes -> AES-256-GCM. Both share a 12-byte nonce. *)
  fun algForKey k =
    if String.size k = 16 then Aead.AesGcm128
    else if String.size k = 32 then Aead.AesGcm256
    else raise Aead.Aead ("TlsRecordProtect: unsupported key length "
                          ^ Int.toString (String.size k))

  fun init {key, iv} : state =
    {key = key, iv = iv, alg = algForKey key, seq = 0}

  fun initWithAlg {key, iv, alg} : state =
    {key = key, iv = iv, alg = alg, seq = 0}

  (* The 64-bit sequence number as a big-endian 8-byte string, then
     left-padded with zeros to `Aead.nonceLen` (12) bytes. RFC 8446 §5.3:
     "The 64-bit record sequence number is encoded in network byte order
     and padded to the left with zeros to iv_length." *)
  fun seqBytes (seq : int) : string =
    let
      (* Encode seq as 8 big-endian bytes. seq is non-negative and fits
         in 63 bits (Int is at least 31 bits on most SML impls, so this
         is well within range for any realistic record count). *)
      val w = Word64.fromInt seq
      fun byte i = Byte.byteToChar
        (Word8.fromLarge (Word64.toLarge (Word64.>> (w, Word.fromInt i))))
      val be8 = String.implode
        [byte 56, byte 48, byte 40, byte 32,
         byte 24, byte 16, byte 8, byte 0]
      val padLen = Aead.nonceLen Aead.AesGcm128 - 8   (* = 4 *)
      val pad = String.implode (List.tabulate (padLen, fn _ => #"\000"))
    in
      pad ^ be8
    end

  (* Per-record nonce = static IV XOR (big-endian seq, left-padded to
     nonceLen). Both operands are nonceLen bytes. *)
  fun nonce {iv, seq} : string =
    let
      val nl = Aead.nonceLen Aead.AesGcm128   (* = 12, same for all algs *)
      val pad = seqBytes seq
      fun xorBytes (a, b) =
        String.implode
          (ListPair.map (fn (c1, c2) =>
            Byte.byteToChar
              (Word8.xorb (Byte.charToByte c1, Byte.charToByte c2)))
            (String.explode a, String.explode b))
    in
      if String.size iv <> nl then
        raise Aead.Aead ("TlsRecordProtect: bad IV length "
                         ^ Int.toString (String.size iv))
      else if String.size pad <> nl then
        raise Aead.Aead ("TlsRecordProtect: internal: seq padding wrong length")
      else xorBytes (iv, pad)
    end

  val maxPlaintext : int = 16384   (* 2^14, RFC 8446 §5.1 *)

  (* Map a TlsRecord.contentType to its wire byte. Mirrors
     TlsRecord.contentTypeToByte, which is not exposed by the opaque
     TLS_RECORD ascription. *)
  fun contentTypeToByte TlsRecord.Invalid          = 0w0
    | contentTypeToByte TlsRecord.ChangeCipherSpec = 0w20
    | contentTypeToByte TlsRecord.Alert            = 0w21
    | contentTypeToByte TlsRecord.Handshake        = 0w22
    | contentTypeToByte TlsRecord.ApplicationData  = 0w23

  fun byteToContentType 0w0  = SOME TlsRecord.Invalid
    | byteToContentType 0w20 = SOME TlsRecord.ChangeCipherSpec
    | byteToContentType 0w21 = SOME TlsRecord.Alert
    | byteToContentType 0w22 = SOME TlsRecord.Handshake
    | byteToContentType 0w23 = SOME TlsRecord.ApplicationData
    | byteToContentType _    = NONE

  (* Build the 5-byte AAD record header for an ApplicationData record
     carrying a ciphertext body of length n: type=0x17, version=0x0303,
     length=n (big-endian). RFC 8446 §5.2: the AAD is the 5-byte record
     header; for encrypted records the outer type is always
     ApplicationData (0x17) and the version is the legacy 0x0303. *)
  fun aadHeader (n : int) : string =
    String.implode [
      Byte.byteToChar 0w23,                               (* ApplicationData *)
      Byte.byteToChar 0w03, Byte.byteToChar 0w03,         (* legacy version *)
      Byte.byteToChar (Word8.fromInt (n div 256)),
      Byte.byteToChar (Word8.fromInt (n mod 256))
    ]

  fun protect {state, innerType, plaintext, pad} : string * state =
    let
      val {key, iv, alg, seq} = state
      (* RFC 8446 §5.1: reject plaintext longer than 2^14. We also
         refuse negative pad (a programming error). *)
      val ptLen = String.size plaintext
      val _ = if ptLen > maxPlaintext then
                raise Aead.Aead ("TlsRecordProtect.protect: record_overflow")
              else if pad < 0 then
                raise Aead.Aead ("TlsRecordProtect.protect: negative pad")
              else ()
      (* TLSInnerPlaintext = plaintext || contentType || zeros(pad) (§5.2). *)
      val inner = plaintext
        ^ String.str (Byte.byteToChar (contentTypeToByte innerType))
        ^ String.implode (List.tabulate (pad, fn _ => #"\000"))
      val n = nonce {iv = iv, seq = seq}
      val aad = aadHeader (String.size inner + Aead.tagLen)
      val sealed = Aead.seal alg
        {key = key, nonce = n, aad = aad, plaintext = inner}
      val st' = {key = key, iv = iv, alg = alg, seq = seq + 1} : state
    in
      (sealed, st')
    end

  fun unprotect {state, record}
      : (TlsRecord.contentType * string * state) option =
    let
      val {key, iv, alg, seq} = state
      val n = nonce {iv = iv, seq = seq}
      val aad = aadHeader (String.size record)
    in
      case Aead.open' alg {key = key, nonce = n, aad = aad, ciphertext = record} of
          NONE => NONE   (* AEAD failure -> caller maps to bad_record_mac *)
        | SOME inner =>
            let
              (* Strip trailing zero padding; the last non-zero byte is
                 the inner content type (§5.2). Walk back from the end. *)
              val len = String.size inner
              fun findType i =
                if i < 0 then NONE   (* all zeros: malformed *)
                else
                  let val b = Byte.charToByte (String.sub (inner, i)) in
                    if b = 0w0 then findType (i - 1)
                    else if i = 0 then NONE  (* only a type byte, no plaintext *)
                    else
                      case byteToContentType b of
                          NONE => NONE
                        | SOME ct => SOME (ct, String.substring (inner, 0, i))
                  end
            in
              case findType (len - 1) of
                  NONE => NONE
                | SOME (ct, pt) =>
                    if String.size pt > maxPlaintext then
                      NONE   (* record_overflow (§5.1) *)
                    else
                      SOME (ct, pt,
                            {key = key, iv = iv, alg = alg, seq = seq + 1} : state)
            end
    end
end
