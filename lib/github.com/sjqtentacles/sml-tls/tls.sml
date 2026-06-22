(* tls.sml

   TLS 1.3 (RFC 8446) implementation, built on the vendored sjqtentacles
   crypto family (sml-kdf for HKDF, sml-aead for AEAD, sml-x25519 for the
   key exchange, sml-codec for SHA-256). Pure and sans-IO: the caller owns
   the transport and feeds bytes to the state machines.

   The key schedule is the heart of the protocol; it is implemented in
   `TlsKeySchedule` and verified byte-for-byte against the RFC 8448 test
   vectors (see test/test.sml). *)

structure TlsRecord :> TLS_RECORD =
struct
  datatype contentType =
      Invalid
    | ChangeCipherSpec
    | Alert
    | Handshake
    | ApplicationData

  fun contentTypeToByte Invalid          = 0w0
    | contentTypeToByte ChangeCipherSpec = 0w20
    | contentTypeToByte Alert            = 0w21
    | contentTypeToByte Handshake        = 0w22
    | contentTypeToByte ApplicationData  = 0w23

  fun byteToContentType 0w0  = SOME Invalid
    | byteToContentType 0w20 = SOME ChangeCipherSpec
    | byteToContentType 0w21 = SOME Alert
    | byteToContentType 0w22 = SOME Handshake
    | byteToContentType 0w23 = SOME ApplicationData
    | byteToContentType _    = NONE

  (* 0x0303 -- TLS 1.2 legacy record version, used on the wire even for 1.3. *)
  val legacyVersion : Word16.word = 0wx0303

  type tlsPlaintext = {contentType : contentType, fragment : string}
  type tlsCiphertext = {contentType : contentType, encryptedRecord : string}

  (* 5-byte header: [type:1][version:2][length:2]. *)
  fun encodePlaintext {contentType, fragment} =
    let
      val n = String.size fragment
      val hdr = String.implode [
        Byte.byteToChar (contentTypeToByte contentType),
        Byte.byteToChar (Word8.fromLarge (Word16.toLarge (Word16.>> (legacyVersion, 0w8)))),
        Byte.byteToChar (Word8.fromLarge (Word16.toLarge (Word16.andb (legacyVersion, 0wxFF)))),
        Byte.byteToChar (Word8.fromInt (n div 256)),
        Byte.byteToChar (Word8.fromInt (n mod 256))
      ]
    in
      hdr ^ fragment
    end

  fun decodePlaintext s =
    if String.size s < 5 then NONE
    else
      let
        val b0 = Byte.charToByte (String.sub (s, 0))
        val hi = Word8.toInt (Byte.charToByte (String.sub (s, 3)))
        val lo = Word8.toInt (Byte.charToByte (String.sub (s, 4)))
        val n = hi * 256 + lo
      in
        case byteToContentType b0 of
            NONE => NONE
          | SOME ct =>
              if String.size s < 5 + n then NONE
              else
                let
                  val frag = String.substring (s, 5, n)
                  val rest = String.extract (s, 5 + n, NONE)
                in
                  SOME ({contentType = ct, fragment = frag}, rest)
                end
      end

  fun encodeCiphertext {contentType, encryptedRecord} =
    encodePlaintext {contentType = contentType, fragment = encryptedRecord}

  fun decodeCiphertext s =
    Option.map
      (fn ({contentType, fragment}, rest) =>
          ({contentType = contentType, encryptedRecord = fragment}, rest))
      (decodePlaintext s)
end

structure TlsAlert :> TLS_ALERT =
struct
  datatype alertLevel = Warning | Fatal

  fun alertLevelToByte Warning = 0w1
    | alertLevelToByte Fatal   = 0w2

  fun byteToAlertLevel 0w1 = SOME Warning
    | byteToAlertLevel 0w2 = SOME Fatal
    | byteToAlertLevel _   = NONE

  datatype alertDescription =
      CloseNotify
    | UnexpectedMessage
    | BadRecordMac
    | RecordOverflow
    | HandshakeFailure
    | BadCertificate
    | UnsupportedCertificate
    | CertificateRevoked
    | CertificateExpired
    | CertificateUnknown
    | IllegalParameter
    | UnknownCa
    | AccessDenied
    | DecodeError
    | DecryptError
    | ProtocolVersion
    | InsufficientSecurity
    | InternalError
    | UserCancelled
    | MissingExtension
    | UnsupportedExtension
    | UnrecognizedName
    | BadCertificateStatus
    | UnknownPskIdentity
    | CertificateRequired
    | NoApplicationProtocol
    | Other of Word8.word

  (* RFC 8446 §6.2 alert description codes (decimal). NOTE: write every
     value in decimal -- mixing `0wNN` (decimal) and `0wxNN` (hex) literals
     here previously mis-encoded a dozen alerts (e.g. protocol_version as
     46 instead of 70, colliding with certificate_unknown). *)
  fun alertDescriptionToByte CloseNotify             = 0w0
    | alertDescriptionToByte UnexpectedMessage       = 0w10
    | alertDescriptionToByte BadRecordMac           = 0w20
    | alertDescriptionToByte RecordOverflow         = 0w22
    | alertDescriptionToByte HandshakeFailure       = 0w40
    | alertDescriptionToByte BadCertificate         = 0w42
    | alertDescriptionToByte UnsupportedCertificate = 0w43
    | alertDescriptionToByte CertificateRevoked     = 0w44
    | alertDescriptionToByte CertificateExpired     = 0w45
    | alertDescriptionToByte CertificateUnknown     = 0w46
    | alertDescriptionToByte IllegalParameter       = 0w47
    | alertDescriptionToByte UnknownCa              = 0w48
    | alertDescriptionToByte AccessDenied           = 0w49
    | alertDescriptionToByte DecodeError            = 0w50
    | alertDescriptionToByte DecryptError           = 0w51
    | alertDescriptionToByte ProtocolVersion        = 0w70
    | alertDescriptionToByte InsufficientSecurity   = 0w71
    | alertDescriptionToByte InternalError          = 0w80
    | alertDescriptionToByte UserCancelled          = 0w90
    | alertDescriptionToByte MissingExtension       = 0w109
    | alertDescriptionToByte UnsupportedExtension   = 0w110
    | alertDescriptionToByte UnrecognizedName       = 0w112
    | alertDescriptionToByte BadCertificateStatus   = 0w113
    | alertDescriptionToByte UnknownPskIdentity     = 0w115
    | alertDescriptionToByte CertificateRequired    = 0w116
    | alertDescriptionToByte NoApplicationProtocol  = 0w120
    | alertDescriptionToByte (Other w)              = w

  fun byteToAlertDescription 0w0  = CloseNotify
    | byteToAlertDescription 0w10 = UnexpectedMessage
    | byteToAlertDescription 0w20 = BadRecordMac
    | byteToAlertDescription 0w22 = RecordOverflow
    | byteToAlertDescription 0w40 = HandshakeFailure
    | byteToAlertDescription 0w42 = BadCertificate
    | byteToAlertDescription 0w43 = UnsupportedCertificate
    | byteToAlertDescription 0w44 = CertificateRevoked
    | byteToAlertDescription 0w45 = CertificateExpired
    | byteToAlertDescription 0w46 = CertificateUnknown
    | byteToAlertDescription 0w47 = IllegalParameter
    | byteToAlertDescription 0w48 = UnknownCa
    | byteToAlertDescription 0w49 = AccessDenied
    | byteToAlertDescription 0w50 = DecodeError
    | byteToAlertDescription 0w51 = DecryptError
    | byteToAlertDescription 0w70 = ProtocolVersion
    | byteToAlertDescription 0w71 = InsufficientSecurity
    | byteToAlertDescription 0w80 = InternalError
    | byteToAlertDescription 0w90 = UserCancelled
    | byteToAlertDescription 0w109 = MissingExtension
    | byteToAlertDescription 0w110 = UnsupportedExtension
    | byteToAlertDescription 0w112 = UnrecognizedName
    | byteToAlertDescription 0w113 = BadCertificateStatus
    | byteToAlertDescription 0w115 = UnknownPskIdentity
    | byteToAlertDescription 0w116 = CertificateRequired
    | byteToAlertDescription 0w120 = NoApplicationProtocol
    | byteToAlertDescription w    = Other w

  type alert = {level : alertLevel, description : alertDescription}

  fun encode {level, description} =
    String.implode [
      Byte.byteToChar (alertLevelToByte level),
      Byte.byteToChar (alertDescriptionToByte description)
    ]

  fun decode s =
    if String.size s <> 2 then NONE
    else
      let
        val l = Byte.charToByte (String.sub (s, 0))
        val d = Byte.charToByte (String.sub (s, 1))
      in
        case byteToAlertLevel l of
            NONE => NONE
          | SOME lvl => SOME {level = lvl, description = byteToAlertDescription d}
      end
end

structure TlsHandshake :> TLS_HANDSHAKE =
struct
  datatype handshakeType =
      ClientHello
    | ServerHello
    | NewSessionTicket
    | EndOfEarlyData
    | EncryptedExtensions
    | Certificate
    | CertificateRequest
    | CertificateVerify
    | Finished
    | KeyUpdate
    | MessageHash

  fun handshakeTypeToByte ClientHello          = 0w1
    | handshakeTypeToByte ServerHello          = 0w2
    | handshakeTypeToByte NewSessionTicket     = 0w4
    | handshakeTypeToByte EndOfEarlyData       = 0w5
    | handshakeTypeToByte EncryptedExtensions  = 0w8
    | handshakeTypeToByte Certificate          = 0w11
    | handshakeTypeToByte CertificateRequest   = 0w13
    | handshakeTypeToByte CertificateVerify    = 0w15
    | handshakeTypeToByte Finished             = 0w20  (* 0x14 *)
    | handshakeTypeToByte KeyUpdate            = 0w24
    | handshakeTypeToByte MessageHash          = 0w254

  fun byteToHandshakeType 0w1   = SOME ClientHello
    | byteToHandshakeType 0w2   = SOME ServerHello
    | byteToHandshakeType 0w4   = SOME NewSessionTicket
    | byteToHandshakeType 0w5   = SOME EndOfEarlyData
    | byteToHandshakeType 0w8   = SOME EncryptedExtensions
    | byteToHandshakeType 0w11  = SOME Certificate
    | byteToHandshakeType 0w13  = SOME CertificateRequest
    | byteToHandshakeType 0w15  = SOME CertificateVerify
    | byteToHandshakeType 0w20  = SOME Finished  (* 0x14 *)
    | byteToHandshakeType 0w24  = SOME KeyUpdate
    | byteToHandshakeType 0w254 = SOME MessageHash
    | byteToHandshakeType _     = NONE

  type handshakeMessage = {msgType : handshakeType, body : string}

  (* 1-byte type, 3-byte big-endian length, body. *)
  fun encodeMessage {msgType, body} =
    let
      val n = String.size body
      val hdr = String.implode [
        Byte.byteToChar (handshakeTypeToByte msgType),
        Byte.byteToChar (Word8.fromInt ((n div 65536) mod 256)),
        Byte.byteToChar (Word8.fromInt ((n div 256) mod 256)),
        Byte.byteToChar (Word8.fromInt (n mod 256))
      ]
    in
      hdr ^ body
    end

  fun decodeMessage s =
    if String.size s < 4 then NONE
    else
      let
        val t = Byte.charToByte (String.sub (s, 0))
        val b1 = Word8.toInt (Byte.charToByte (String.sub (s, 1)))
        val b2 = Word8.toInt (Byte.charToByte (String.sub (s, 2)))
        val b3 = Word8.toInt (Byte.charToByte (String.sub (s, 3)))
        val n = b1 * 65536 + b2 * 256 + b3
      in
        case byteToHandshakeType t of
            NONE => NONE
          | SOME ht =>
              if String.size s < 4 + n then NONE
              else
                let
                  val body = String.substring (s, 4, n)
                  val rest = String.extract (s, 4 + n, NONE)
                in
                  SOME ({msgType = ht, body = body}, rest)
                end
      end

  (* ---- Extensions (§4.2) ---- *)
  type extension = {extType : Word16.word, data : string}

  fun word16ToBytes w =
    String.implode [
      Byte.byteToChar (Word8.fromLarge (Word16.toLarge (Word16.>> (w, 0w8)))),
      Byte.byteToChar (Word8.fromLarge (Word16.toLarge (Word16.andb (w, 0wxFF))))
    ]

  fun bytesToWord16 (hi, lo) =
    Word16.orb (Word16.<< (Word16.fromLarge (Word8.toLarge hi), 0w8),
                Word16.fromLarge (Word8.toLarge lo))

  fun encodeExtensions exts =
    let
      val total = List.foldl (fn ({data, ...}, n) => n + 4 + String.size data) 0 exts
      val header = word16ToBytes (Word16.fromInt total)
      fun one {extType, data} =
        word16ToBytes extType ^ word16ToBytes (Word16.fromInt (String.size data)) ^ data
    in
      header ^ String.concat (List.map one exts)
    end

  fun decodeExtensions s =
    if String.size s < 2 then NONE
    else
      let
        val total = Word16.toInt (bytesToWord16
          (Byte.charToByte (String.sub (s, 0)), Byte.charToByte (String.sub (s, 1))))
        exception Bad
        fun loop (i, acc) =
          if i >= 2 + total then SOME (List.rev acc)
          else
            if i + 4 > String.size s then NONE
            else
              let
                val et = bytesToWord16 (Byte.charToByte (String.sub (s, i)),
                                        Byte.charToByte (String.sub (s, i + 1)))
                val dl = Word16.toInt (bytesToWord16
                  (Byte.charToByte (String.sub (s, i + 2)),
                   Byte.charToByte (String.sub (s, i + 3))))
              in
                if i + 4 + dl > String.size s then NONE
                else
                  let val d = String.substring (s, i + 4, dl)
                  in loop (i + 4 + dl, {extType = et, data = d} :: acc) end
              end
      in
        if String.size s < 2 + total then NONE
        else (loop (2, []) handle Bad => NONE)
      end

  val extServerName          : Word16.word = 0wx0000
  val extSupportedGroups     : Word16.word = 0wx000A
  val extSignatureAlgorithms : Word16.word = 0wx000D
  val extSupportedVersions   : Word16.word = 0wx002B
  val extKeyShare            : Word16.word = 0wx0033
  val extPreSharedKey        : Word16.word = 0wx0029
  val extEarlyData           : Word16.word = 0wx002A
  val extCookie              : Word16.word = 0wx002C
  val extPskKeyExchangeModes : Word16.word = 0wx002D

  (* SHA-256("HelloRetryRequest") -- RFC 8446 §4.1.3. *)
  val helloRetryRequestRandom : string =
    String.implode (List.map Char.chr [
      0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
      0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
      0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
      0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
    ])

  (* ---- ClientHello (§4.1.2) ---- *)
  type clientHello = {
    legacyVersion : Word16.word,
    random        : string,
    legacySessionId : string,
    cipherSuites  : Word16.word list,
    legacyCompression : Word8.word list,
    extensions    : extension list
  }

  fun encodeWord16List ws =
    let
      val total = List.length ws * 2
      val body = String.concat (List.map word16ToBytes ws)
    in
      word16ToBytes (Word16.fromInt total) ^ body
    end

  fun encodeWord8List ws =
    let
      val total = List.length ws
      val body = String.implode (List.map Byte.byteToChar ws)
    in
      String.str (Char.chr total) ^ body
    end

  fun encodeClientHello {legacyVersion, random, legacySessionId,
                         cipherSuites, legacyCompression, extensions} =
    let
      val sessionIdLen = String.size legacySessionId
      val sessionIdBytes = String.str (Char.chr sessionIdLen) ^ legacySessionId
      val extBlock = encodeExtensions extensions
    in
      word16ToBytes legacyVersion
      ^ random
      ^ sessionIdBytes
      ^ encodeWord16List cipherSuites
      ^ encodeWord8List legacyCompression
      ^ extBlock
    end

  (* Decode the body of a ClientHello. Returns NONE on structural errors.
     Uses a local exception to short-circuit on the first parse failure,
     keeping the happy path flat and readable. *)
  fun decodeClientHello s =
    let
      val len = String.size s
      exception Bad
      fun at i =
        if i < len then Byte.charToByte (String.sub (s, i)) else raise Bad
      fun w16 i =
        if i + 1 < len then
          bytesToWord16 (Byte.charToByte (String.sub (s, i)),
                         Byte.charToByte (String.sub (s, i + 1)))
        else raise Bad
      fun sub (i, n) =
        if i + n <= len then String.substring (s, i, n) else raise Bad
    in
      SOME (let
        val legacyVersion = w16 0
        val random = sub (2, 32)
        val sidLen = Word8.toInt (at 34)
        val sidStart = 35
        val legacySessionId = sub (sidStart, sidLen)
        val csStart = sidStart + sidLen
        val csTotal = Word16.toInt (w16 csStart)
        val csCount = csTotal div 2
        val csBodyStart = csStart + 2
        fun readCS (i, 0, acc) = (List.rev acc, i)
          | readCS (i, k, acc) = readCS (i + 2, k - 1, w16 i :: acc)
        val (cipherSuites, compStart) = readCS (csBodyStart, csCount, [])
        val compLen = Word8.toInt (at compStart)
        val compBodyStart = compStart + 1
        fun readComp (i, 0, acc) = (List.rev acc, i)
          | readComp (i, k, acc) = readComp (i + 1, k - 1, at i :: acc)
        val (legacyCompression, extStart) = readComp (compBodyStart, compLen, [])
        val extensions =
          if extStart >= len then []
          else
            case decodeExtensions (String.extract (s, extStart, NONE)) of
                NONE => raise Bad
              | SOME es => es
      in
        {
          legacyVersion = legacyVersion,
          random = random,
          legacySessionId = legacySessionId,
          cipherSuites = cipherSuites,
          legacyCompression = legacyCompression,
          extensions = extensions
        } : clientHello
      end) handle Bad => NONE
    end

  (* ---- ServerHello (§4.1.3) ---- *)
  type serverHello = {
    legacyVersion : Word16.word,
    random        : string,
    legacySessionId : string,
    cipherSuite   : Word16.word,
    legacyCompression : Word8.word,
    extensions    : extension list
  }

  fun encodeServerHello {legacyVersion, random, legacySessionId,
                         cipherSuite, legacyCompression, extensions} =
    let
      val sessionIdLen = String.size legacySessionId
      val extBlock = encodeExtensions extensions
    in
      word16ToBytes legacyVersion
      ^ random
      ^ String.str (Char.chr sessionIdLen) ^ legacySessionId
      ^ word16ToBytes cipherSuite
      ^ String.str (Byte.byteToChar legacyCompression)
      ^ extBlock
    end

  fun decodeServerHello s =
    let
      val len = String.size s
      exception Bad
      fun at i =
        if i < len then Byte.charToByte (String.sub (s, i)) else raise Bad
      fun w16 i =
        if i + 1 < len then
          bytesToWord16 (Byte.charToByte (String.sub (s, i)),
                         Byte.charToByte (String.sub (s, i + 1)))
        else raise Bad
      fun sub (i, n) =
        if i + n <= len then String.substring (s, i, n) else raise Bad
    in
      SOME (let
        val legacyVersion = w16 0
        val random = sub (2, 32)
        val sidLen = Word8.toInt (at 34)
        val sidStart = 35
        val legacySessionId = sub (sidStart, sidLen)
        val csStart = sidStart + sidLen
        val cipherSuite = w16 csStart
        val compStart = csStart + 2
        val legacyCompression = at compStart
        val extStart = compStart + 1
        val extensions =
          if extStart >= len then []
          else
            case decodeExtensions (String.extract (s, extStart, NONE)) of
                NONE => raise Bad
              | SOME es => es
      in
        {
          legacyVersion = legacyVersion,
          random = random,
          legacySessionId = legacySessionId,
          cipherSuite = cipherSuite,
          legacyCompression = legacyCompression,
          extensions = extensions
        } : serverHello
      end) handle Bad => NONE
    end

  (* ---- EncryptedExtensions (§4.3.1) ---- *)
  type encryptedExtensions = extension list

  fun encodeEncryptedExtensions exts = encodeExtensions exts
  fun decodeEncryptedExtensions s = decodeExtensions s

  (* ---- Certificate (§4.4.2) ---- *)
  type certificateEntry = {certData : string, extensions : extension list}
  type certificate = {
    certificateRequestContext : string,
    certificateList           : certificateEntry list
  }

  (* 3-byte big-endian length prefix, used for the certificate list and each
     entry / cert data field. *)
  fun len3 n = String.implode [
    Byte.byteToChar (Word8.fromInt ((n div 65536) mod 256)),
    Byte.byteToChar (Word8.fromInt ((n div 256) mod 256)),
    Byte.byteToChar (Word8.fromInt (n mod 256))
  ]

  fun readLen3 (s, i) =
    if i + 3 > String.size s then NONE
    else
      let
        val b1 = Word8.toInt (Byte.charToByte (String.sub (s, i)))
        val b2 = Word8.toInt (Byte.charToByte (String.sub (s, i + 1)))
        val b3 = Word8.toInt (Byte.charToByte (String.sub (s, i + 2)))
      in
        SOME (b1 * 65536 + b2 * 256 + b3, i + 3)
      end

  fun encodeCertificate {certificateRequestContext, certificateList} =
    let
      (* RFC 8446 sec 4.4.2: certificate_request_context is opaque<0..2^8-1>,
         i.e. a SINGLE-byte length prefix (not 3 bytes). *)
      val ctxLen = String.size certificateRequestContext
      val ctx = String.str (Char.chr (ctxLen mod 256)) ^ certificateRequestContext
      fun oneEntry {certData, extensions} =
        len3 (String.size certData) ^ certData ^ encodeExtensions extensions
      val entries = String.concat (List.map oneEntry certificateList)
      val entriesLen = String.size entries
    in
      ctx ^ len3 entriesLen ^ entries
    end

  fun decodeCertificate s =
    let
      val len = String.size s
    in
      (* RFC 8446 sec 4.4.2: certificate_request_context has a 1-byte length. *)
      if len < 1 then NONE
      else
        let
          val ctxLen = Word8.toInt (Byte.charToByte (String.sub (s, 0)))
          val i = 1
        in
            if i + ctxLen > len then NONE
            else
              let
                val ctx = String.substring (s, i, ctxLen)
                val listStart = i + ctxLen
              in
                case readLen3 (s, listStart) of
                    NONE => NONE
                  | SOME (total, i') =>
                      if i' + total > len then NONE
                      else
                        let
                          val block = String.substring (s, i', total)
                          val blen = String.size block
                          fun loop (k, acc) =
                            if k >= blen then SOME (List.rev acc)
                            else
                              (case readLen3 (block, k) of
                                  NONE => NONE
                                | SOME (cl, certDataStart) =>
                                    if certDataStart + cl > blen then NONE
                                    else
                                      let
                                        val certData = String.substring (block, certDataStart, cl)
                                        val extStart = certDataStart + cl
                                      in
                                        if extStart >= blen then
                                          loop (blen, {certData = certData, extensions = []} :: acc)
                                        else
                                          case decodeExtensions (String.extract (block, extStart, NONE)) of
                                              NONE => NONE
                                            | SOME es =>
                                                let
                                                  val entryEnd = extStart + String.size (encodeExtensions es)
                                                in
                                                  loop (entryEnd, {certData = certData, extensions = es} :: acc)
                                                end
                                      end)
                        in
                          case loop (0, []) of
                              NONE => NONE
                            | SOME entries =>
                                SOME {certificateRequestContext = ctx,
                                      certificateList = entries}
                        end
              end
        end
    end

  (* ---- CertificateVerify (§4.4.3) ---- *)
  type certificateVerify = {sigAlg : Word16.word, sigBytes : string}

  (* RFC 8446 sec 4.4.3: signature is opaque<0..2^16-1>, i.e. a 2-byte
     length prefix (not 3 bytes). *)
  fun encodeCertificateVerify {sigAlg, sigBytes} =
    word16ToBytes sigAlg
    ^ word16ToBytes (Word16.fromInt (String.size sigBytes)) ^ sigBytes

  fun decodeCertificateVerify s =
    if String.size s < 4 then NONE
    else
      let
        val sigAlg = bytesToWord16 (Byte.charToByte (String.sub (s, 0)),
                                    Byte.charToByte (String.sub (s, 1)))
        val n = Word16.toInt (bytesToWord16
                  (Byte.charToByte (String.sub (s, 2)),
                   Byte.charToByte (String.sub (s, 3))))
        val i = 4
      in
        if i + n > String.size s then NONE
        else SOME {sigAlg = sigAlg, sigBytes = String.substring (s, i, n)}
      end

  (* ---- Finished (§4.4.4) ---- *)
  type finished = {verifyData : string}

  fun encodeFinished {verifyData} = verifyData

  fun decodeFinished s =
    if String.size s = 0 then NONE
    else SOME {verifyData = s}

  (* ---- NewSessionTicket (§4.6.1) ---- *)
  type newSessionTicket = {
    ticketLifetime   : Word32.word,
    ticketAgeAdd     : Word32.word,
    ticketNonce      : string,
    ticket           : string,
    extensions       : extension list
  }

  fun word32ToBytes w =
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

  fun encodeNewSessionTicket {ticketLifetime, ticketAgeAdd, ticketNonce,
                              ticket, extensions} =
    word32ToBytes ticketLifetime
    ^ word32ToBytes ticketAgeAdd
    ^ String.str (Char.chr (String.size ticketNonce)) ^ ticketNonce
    ^ len3 (String.size ticket) ^ ticket
    ^ encodeExtensions extensions

  fun decodeNewSessionTicket s =
    if String.size s < 8 then NONE
    else
      let
        val ticketLifetime = bytesToWord32
          (Byte.charToByte (String.sub (s, 0)), Byte.charToByte (String.sub (s, 1)),
           Byte.charToByte (String.sub (s, 2)), Byte.charToByte (String.sub (s, 3)))
        val ticketAgeAdd = bytesToWord32
          (Byte.charToByte (String.sub (s, 4)), Byte.charToByte (String.sub (s, 5)),
           Byte.charToByte (String.sub (s, 6)), Byte.charToByte (String.sub (s, 7)))
      in
        if String.size s < 9 then NONE
        else
          let
            val nonceLen = Word8.toInt (Byte.charToByte (String.sub (s, 8)))
          in
            if 9 + nonceLen > String.size s then NONE
            else
              let
                val ticketNonce = String.substring (s, 9, nonceLen)
                val ticketStart = 9 + nonceLen
              in
                case readLen3 (s, ticketStart) of
                    NONE => NONE
                  | SOME (tl, i) =>
                      if i + tl > String.size s then NONE
                      else
                        let
                          val ticket = String.substring (s, i, tl)
                          val extStart = i + tl
                        in
                          if extStart >= String.size s then
                            SOME {ticketLifetime = ticketLifetime,
                                  ticketAgeAdd = ticketAgeAdd,
                                  ticketNonce = ticketNonce,
                                  ticket = ticket,
                                  extensions = []}
                          else
                            case decodeExtensions (String.extract (s, extStart, NONE)) of
                                NONE => NONE
                              | SOME exts =>
                                  SOME {ticketLifetime = ticketLifetime,
                                        ticketAgeAdd = ticketAgeAdd,
                                        ticketNonce = ticketNonce,
                                        ticket = ticket,
                                        extensions = exts}
                        end
              end
          end
      end

  (* ---- Cipher suites (§B.4) ---- *)
  val suiteTlsAes128GcmSha256   : Word16.word = 0wx1301
  val suiteTlsAes256GcmSha384   : Word16.word = 0wx1302
  val suiteTlsChaCha20Poly1305  : Word16.word = 0wx1303

  (* ---- Signature schemes (§4.2.3 / RFC 8017) ---- *)
  val sigRsaPssRsaSha256 : Word16.word = 0wx0804
  val sigRsaPssRsaSha384 : Word16.word = 0wx0805
  val sigRsaPssRsaSha512 : Word16.word = 0wx0806
  val sigEcdsaSecp256r1Sha256 : Word16.word = 0wx0403

  (* ---- Named groups (§4.2.7) ---- *)
  val groupX25519 : Word16.word = 0wx001D
  val groupSecp256r1 : Word16.word = 0wx0017
end

structure TlsKeySchedule :> TLS_KEY_SCHEDULE =
struct
  val hashLen = 32  (* SHA-256 *)

  val zeros =
    String.implode (List.tabulate (hashLen, fn _ => #"\000"))

  (* "tls13 " prefix per RFC 8446 §7.1. *)
  val tls13Prefix = "tls13 "

  (* HKDF-Expand-Label. Uses Kdf.Hkdf.expand with HmacSha256. *)
  fun hkdfExpandLabel {secret, label, context, length} =
    let
      val fullLabel = tls13Prefix ^ label
      val labelLen = String.size fullLabel
      val ctxLen = String.size context
      (* HkdfLabel structure:
           uint16 length;
           opaque label<7..255>;     (* 1-byte length prefix *)
           opaque context<0..255>;   (* 1-byte length prefix *)
         Total info = 2 + 1 + labelLen + 1 + ctxLen bytes. *)
      val info =
        String.implode [
          Byte.byteToChar (Word8.fromInt ((length div 256) mod 256)),
          Byte.byteToChar (Word8.fromInt (length mod 256)),
          Byte.byteToChar (Word8.fromInt labelLen)
        ]
        ^ fullLabel
        ^ String.str (Char.chr ctxLen)
        ^ context
    in
      Kdf.Hkdf.expand Kdf.HmacSha256
        {prk = secret, info = info, len = length}
    end

  (* Hash the transcript with SHA-256 (sml-codec's Sha256.digest). *)
  fun transcriptHash transcript = Sha256.digest transcript

  fun deriveSecret {secret, label, transcript} =
    hkdfExpandLabel {secret = secret, label = label,
                     context = transcriptHash transcript, length = hashLen}

  (* HKDF-Extract with SHA-256. *)
  fun extract {salt, ikm} =
    Kdf.Hkdf.extract Kdf.HmacSha256 {salt = salt, ikm = ikm}

  val deriveLabel = "derived"

  fun earlySecret {psk} =
    extract {salt = zeros, ikm = psk}

  (* The empty-string transcript hash, used as the context for the "derived"
     label between HKDF-Extract stages (RFC 8446 §7.1:
     Derive-Secret(., "derived", "") = HKDF-Expand-Label(., "derived",
     Hash(""), Hash.length)). *)
  val emptyHash = Sha256.digest ""

  fun handshakeSecret {earlySecret, dhe} =
    let
      val derived = hkdfExpandLabel {secret = earlySecret, label = deriveLabel,
                                     context = emptyHash, length = hashLen}
    in
      extract {salt = derived, ikm = dhe}
    end

  fun masterSecret {handshakeSecret} =
    let
      val derived = hkdfExpandLabel {secret = handshakeSecret, label = deriveLabel,
                                     context = emptyHash, length = hashLen}
    in
      extract {salt = derived, ikm = zeros}
    end

  fun trafficKey {secret, keyLength} =
    hkdfExpandLabel {secret = secret, label = "key", context = "", length = keyLength}

  fun trafficIv {secret, ivLength} =
    hkdfExpandLabel {secret = secret, label = "iv", context = "", length = ivLength}

  fun finishedKey {secret} =
    hkdfExpandLabel {secret = secret, label = "finished", context = "", length = hashLen}

  val certificateVerifyPrefix =
    String.implode (List.tabulate (64, fn _ => #" "))

  val clientCertVerifyContext = "TLS 1.3, client CertificateVerify"
  val serverCertVerifyContext = "TLS 1.3, server CertificateVerify"

  (* RFC 8446 sec. 4.4.3: 64 octets of 0x20, the context string, a single
     0x00 octet, then the content (transcript hash) to be signed. *)
  fun certificateVerifyInput {contextString, transcriptHash} =
    certificateVerifyPrefix ^ contextString ^ String.str (Char.chr 0) ^ transcriptHash

  (* rsa_pss_rsae_sha256 (RFC 8446 §4.2.3): SHA-256 + RSA-PSS, salt = 32. *)
  val sigRsaPssRsaeSha256 = 0wx0804 : Word16.word
  (* Fixed 32-byte (all-zero) PSS salt so signatures are reproducible across
     MLton and Poly/ML. *)
  val cvFixedSalt = String.implode (List.tabulate (32, fn _ => Char.chr 0))

  fun signServerCertVerify {priv, sigAlg, transcript} =
    if sigAlg = sigRsaPssRsaeSha256 then
      let
        val input = certificateVerifyInput
          {contextString = serverCertVerifyContext,
           transcriptHash = transcriptHash transcript}
      in
        Rsa.signPss {priv = priv, hash = Rsa.SHA256, salt = cvFixedSalt,
                     msg = input}
      end
    else raise Fail "signServerCertVerify: unsupported signature scheme"

  fun verifyServerCertVerify {pub, sigAlg, transcript, sgn} =
    if sigAlg = sigRsaPssRsaeSha256 then
      let
        val input = certificateVerifyInput
          {contextString = serverCertVerifyContext,
           transcriptHash = transcriptHash transcript}
      in
        Rsa.verifyPss {pub = pub, hash = Rsa.SHA256, saltLen = 32,
                       msg = input, sgn = sgn}
      end
    else false

  fun finishedVerifyData {finishedKey, transcript} =
    Hmac.hmacSha256 finishedKey (transcriptHash transcript)

  (* ---- PSK resumption (RFC 8446 §4.6.1, §7.1, §4.2.11) ---- *)

  fun resumptionMasterSecret {masterSecret, transcript} =
    deriveSecret {secret = masterSecret, label = "res master",
                  transcript = transcript}

  fun resumptionPsk {resumptionMasterSecret, ticketNonce} =
    hkdfExpandLabel {secret = resumptionMasterSecret, label = "resumption",
                     context = ticketNonce, length = hashLen}

  (* binder_key = Derive-Secret(Early-Secret(PSK), "res binder", "") *)
  fun binderKey {psk} =
    let val es = extract {salt = zeros, ikm = psk}
    in deriveSecret {secret = es, label = "res binder", transcript = ""} end

  fun binderFinishedKey {psk} =
    hkdfExpandLabel {secret = binderKey {psk = psk}, label = "finished",
                     context = "", length = hashLen}

  fun pskBinder {psk, transcript} =
    Hmac.hmacSha256 (binderFinishedKey {psk = psk}) (transcriptHash transcript)

  type keySchedule = {
    earlySecret       : string,
    handshakeSecret   : string,
    masterSecret      : string,
    clientHandshakeSecret : string,
    serverHandshakeSecret : string,
    clientAppSecret       : string,
    serverAppSecret       : string
  }

  fun schedule {dhe, handshakeTranscript, applicationTranscript} =
    let
      val es = earlySecret {psk = zeros}
      val hs = handshakeSecret {earlySecret = es, dhe = dhe}
      val ms = masterSecret {handshakeSecret = hs}
      val cHs = deriveSecret {secret = hs, label = "c hs traffic",
                              transcript = handshakeTranscript}
      val sHs = deriveSecret {secret = hs, label = "s hs traffic",
                              transcript = handshakeTranscript}
      val cAp = deriveSecret {secret = ms, label = "c ap traffic",
                              transcript = applicationTranscript}
      val sAp = deriveSecret {secret = ms, label = "s ap traffic",
                              transcript = applicationTranscript}
    in
      {earlySecret = es, handshakeSecret = hs, masterSecret = ms,
       clientHandshakeSecret = cHs, serverHandshakeSecret = sHs,
       clientAppSecret = cAp, serverAppSecret = sAp}
    end
end
