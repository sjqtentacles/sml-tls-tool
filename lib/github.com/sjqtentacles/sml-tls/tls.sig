(* tls.sig

   TLS 1.3 (RFC 8446) as a pure, sans-IO state machine.

   Philosophy
   ----------
   This library implements the TLS 1.3 protocol *logic* with no network I/O
   and no global state. The caller owns the transport: it feeds bytes received
   from the peer to `TlsClient.step` / `TlsServer.step`, receives back the
   bytes to send (if any) and the updated state, and is responsible for
   actually putting them on the wire. This makes the handshake fully
   deterministic and testable against fixed RFC 8448 vectors: identical inputs
   produce byte-identical outputs on both MLton and Poly/ML.

   All crypto primitives are provided by the vendored sjqtentacles crypto
   family:

     - sml-kdf    : HKDF (RFC 5869) -- the key schedule's core primitive
     - sml-aead   : AES-128/256-GCM + ChaCha20-Poly1305 -- TLS 1.3 AEAD
     - sml-x25519 : Curve25519 Diffie-Hellman (RFC 7748) -- key exchange
     - sml-codec  : SHA-256 (transcript hashes), Base64
     - sml-x509   : X.509 certificate parsing
     - sml-rsa    : RSA-PSS for CertificateVerify

   Conventions (shared with the rest of the sjqtentacles crypto family):
   - All byte payloads (records, handshake fragments, keys, nonces) are RAW
     BYTE STRINGS (one char per byte, 0-255), never hex.
   - Every datatype is total and exhaustive; decoding a malformed input
     returns `NONE` (or raises `Tls` for programming errors) rather than
     truncating or producing a partial result.
   - The `TlsClient` and `TlsServer` structures are sealed opaquely (`:>`),
     so the concrete state representation is hidden; only the documented
     transitions are observable. *)

signature TLS_RECORD =
sig
  (* RFC 8446 §4 / §5.1: the high-level content types carried by records.
     `invalid` is the all-zero value used in TLSCiphertext once the real type
     is hidden under the AEAD layer. *)
  datatype contentType =
      Invalid
    | ChangeCipherSpec
    | Alert
    | Handshake
    | ApplicationData

  val contentTypeToByte   : contentType -> Word8.word
  val byteToContentType   : Word8.word -> contentType option

  (* RFC 8446 §5.1: the legacy record version field is always 0x0303 (TLS 1.2)
     on the wire, even though this is TLS 1.3. *)
  val legacyVersion : Word16.word

  (* TLSPlaintext: an unencrypted record {type, legacy_record_version, fragment}. *)
  type tlsPlaintext = {contentType : contentType, fragment : string}

  (* TLSCiphertext: an encrypted record. `encryptedRecord` is the
     plaintext-fragment || AEAD-tag produced by `Aead.seal`; the
     `contentType` here is the *outer* type (always ApplicationData once
     encrypted under a traffic key, per §5.2). *)
  type tlsCiphertext = {contentType : contentType, encryptedRecord : string}

  (* Encode/decode the on-the-wire record header + body. `encodePlaintext`
     produces the 5-byte header (type, version, length) followed by the
     fragment; `decodePlaintext` is its inverse and returns `NONE` on a
     truncated header, a bad length, or an unknown content type. *)
  val encodePlaintext : tlsPlaintext -> string
  val decodePlaintext : string -> (tlsPlaintext * string) option
      (* The second element of the result is any trailing bytes after the
         decoded record (so a caller can parse a stream of records). *)

  val encodeCiphertext : tlsCiphertext -> string
  val decodeCiphertext : string -> (tlsCiphertext * string) option
end

signature TLS_ALERT =
sig
  (* RFC 8446 §6: alert levels. *)
  datatype alertLevel = Warning | Fatal

  (* RFC 8446 §6.2: a representative subset of alert descriptions. `close_notify`
     (0) signals an orderly shutdown; the rest are error conditions. *)
  datatype alertDescription =
      CloseNotify                (* 0  *)
    | UnexpectedMessage          (* 10 *)
    | BadRecordMac              (* 20 *)
    | RecordOverflow            (* 22 *)
    | HandshakeFailure          (* 40 *)
    | BadCertificate            (* 42 *)
    | UnsupportedCertificate    (* 43 *)
    | CertificateRevoked        (* 44 *)
    | CertificateExpired        (* 45 *)
    | CertificateUnknown        (* 46 *)
    | IllegalParameter          (* 47 *)
    | UnknownCa                 (* 48 *)
    | AccessDenied              (* 49 *)
    | DecodeError               (* 50 *)
    | DecryptError              (* 51 *)
    | ProtocolVersion           (* 70 *)
    | InsufficientSecurity      (* 71 *)
    | InternalError             (* 80 *)
    | UserCancelled             (* 90 *)
    | MissingExtension          (* 109 *)
    | UnsupportedExtension      (* 110 *)
    | UnrecognizedName          (* 112 *)
    | BadCertificateStatus      (* 113 *)
    | UnknownPskIdentity        (* 115 *)
    | CertificateRequired       (* 116 *)
    | NoApplicationProtocol     (* 120 *)
    | Other of Word8.word       (* any unmapped value, round-tripped  *)

  val alertLevelToByte      : alertLevel -> Word8.word
  val byteToAlertLevel      : Word8.word -> alertLevel option
  val alertDescriptionToByte: alertDescription -> Word8.word
  val byteToAlertDescription: Word8.word -> alertDescription

  type alert = {level : alertLevel, description : alertDescription}

  (* A 2-byte body: [level, description]. This is the *fragment* of an Alert
     record (i.e. what is AEAD-protected under a traffic key). *)
  val encode : alert -> string
  val decode : string -> alert option
end

signature TLS_HANDSHAKE =
sig
  (* RFC 8446 §4: handshake message types. *)
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
    | MessageHash           (* §4.4.1 synthetic message used in transcript *)

  val handshakeTypeToByte : handshakeType -> Word8.word
  val byteToHandshakeType : Word8.word -> handshakeType option

  (* A raw handshake message: {type, body}. The on-the-wire form is a 1-byte
     type, a 3-byte big-endian length, then the body. The transcript hash
     is computed over these wire-form messages. *)
  type handshakeMessage = {msgType : handshakeType, body : string}

  val encodeMessage : handshakeMessage -> string
  val decodeMessage : string -> (handshakeMessage * string) option

  (* ---- Extension framing (§4.2) ----
     An extension on the wire is a 2-byte type, a 2-byte length, and that
     many bytes of data. The helpers below encode/decode a list of
     (extensionType, data) pairs as the extension block of a ClientHello /
     ServerHello / EncryptedExtensions. *)
  type extension = {extType : Word16.word, data : string}

  val encodeExtensions : extension list -> string
  val decodeExtensions : string -> extension list option

  (* A handful of extension type codes we care about. *)
  val extServerName          : Word16.word  (* 0  *)
  val extSupportedGroups     : Word16.word  (* 10 *)
  val extSignatureAlgorithms : Word16.word  (* 13 *)
  val extSupportedVersions   : Word16.word  (* 43 *)
  val extKeyShare            : Word16.word  (* 51 *)

  (* ---- ClientHello (§4.1.2) ----
     The fields kept are the subset needed for a deterministic 1-RTT
     handshake against RFC 8448 vectors. `legacySessionId` is echoed back
     by the server in ServerHello (middlebox compatibility, §4.1.3). *)
  type clientHello = {
    legacyVersion : Word16.word,
    random        : string,           (* 32 bytes                        *)
    legacySessionId : string,
    cipherSuites  : Word16.word list,
    legacyCompression : Word8.word list,
    extensions    : extension list
  }

  val encodeClientHello : clientHello -> string     (* body only, no hdr *)
  val decodeClientHello : string -> clientHello option

  (* ---- ServerHello (§4.1.3) ---- *)
  type serverHello = {
    legacyVersion : Word16.word,
    random        : string,           (* 32 bytes                        *)
    legacySessionId : string,
    cipherSuite   : Word16.word,
    legacyCompression : Word8.word,
    extensions    : extension list
  }

  val encodeServerHello : serverHello -> string
  val decodeServerHello : string -> serverHello option

  (* ---- EncryptedExtensions (§4.3.1) ----
     Just an extension block. *)
  type encryptedExtensions = extension list

  val encodeEncryptedExtensions : encryptedExtensions -> string
  val decodeEncryptedExtensions : string -> encryptedExtensions option

  (* ---- Certificate (§4.4.2) ----
     TLS 1.3 certificate list. Each entry is a DER-encoded certificate plus
     a (possibly empty) list of extensions. The `certificateRequestContext`
     is empty for a 1-RTT handshake. *)
  type certificateEntry = {certData : string, extensions : extension list}
  type certificate = {
    certificateRequestContext : string,
    certificateList           : certificateEntry list
  }

  val encodeCertificate : certificate -> string
  val decodeCertificate : string -> certificate option

  (* ---- CertificateVerify (§4.4.3) ----
     A signature over the concatenation of 64 spaces, the context string,
     a single space, and the transcript hash. We store the signature
     algorithm and the raw signature bytes; verification is done by the
     caller via sml-rsa (RSA-PSS). *)
  type certificateVerify = {sigAlg : Word16.word, sigBytes : string}

  val encodeCertificateVerify : certificateVerify -> string
  val decodeCertificateVerify : string -> certificateVerify option

  (* ---- Finished (§4.4.4) ----
     The verify_data is HMAC over the transcript hash with the finished_key. *)
  type finished = {verifyData : string}

  val encodeFinished : finished -> string
  val decodeFinished : string -> finished option

  (* ---- NewSessionTicket (§4.6.1) ---- *)
  type newSessionTicket = {
    ticketLifetime   : Word32.word,
    ticketAgeAdd     : Word32.word,
    ticketNonce      : string,
    ticket           : string,
    extensions       : extension list
  }

  val encodeNewSessionTicket : newSessionTicket -> string
  val decodeNewSessionTicket : string -> newSessionTicket option

  (* ---- Cipher suites we recognise (§B.4) ---- *)
  val suiteTlsAes128GcmSha256   : Word16.word  (* 0x1301 *)
  val suiteTlsAes256GcmSha384   : Word16.word  (* 0x1302 *)
  val suiteTlsChaCha20Poly1305  : Word16.word  (* 0x1303 *)

  (* ---- Signature schemes (§4.2.3 / RFC 8017) ---- *)
  val sigRsaPssRsaSha256 : Word16.word  (* 0x0804 *)
  val sigRsaPssRsaSha384 : Word16.word  (* 0x0805 *)
  val sigRsaPssRsaSha512 : Word16.word  (* 0x0806 *)
  val sigEcdsaSecp256r1Sha256 : Word16.word  (* 0x0403 *)

  (* ---- Named groups (§4.2.7) ---- *)
  val groupX25519 : Word16.word  (* 0x001d *)

  (* ---- Shared wire helpers ----
     Exposed so the client/server state machines can build and parse the
     extension bodies (key_share, supported_versions, ...) without
     re-implementing the 16-bit big-endian encoding. *)
  val word16ToBytes : Word16.word -> string
  val bytesToWord16 : Word8.word * Word8.word -> Word16.word
end

signature TLS_KEY_SCHEDULE =
sig
  (* The hash function used for the transcript and HKDF. TLS 1.3's key
     schedule is parameterised by the cipher suite's hash; this implementation
     targets SHA-256 (the AES-128-GCM-SHA256 and ChaCha20-Poly1305-SHA256
     suites), which is what the RFC 8448 test vectors use. *)
  val hashLen : int   (* 32 for SHA-256 *)

  (* The zero byte string of `hashLen` bytes -- the "0" input used at several
     points in the key schedule (e.g. the PSK input when there is no PSK). *)
  val zeros : string

  (* HKDF-Expand-Label (RFC 8446 §7.1):
       HkdfExpandLabel(secret, label, context, length) =
         HKDF-Expand(secret, HkdfLabel, length)
     where
       HkdfLabel = struct {
         length: uint16,                  (* the requested length          *)
         label:   opaque[length<255],     (* "tls13 " + label, 7..255 bytes*)
         context: opaque[length<255]      (* usually Hash(transcript)      *)
       }
     The on-the-wire HkdfLabel is: 2-byte length, 1-byte label length, the
     label bytes ("tls13 " ^ label), 1-byte context length, the context. *)
  val hkdfExpandLabel : {secret : string, label : string, context : string, length : int} -> string

  (* Derive-Secret (RFC 8446 §7.1):
       DeriveSecret(secret, label, transcript) =
         HkdfExpandLabel(secret, label, Hash(transcript), Hash.length)
     `transcript` is the *concatenated wire-form handshake messages* so far;
     we hash it here. *)
  val deriveSecret : {secret : string, label : string, transcript : string} -> string

  (* The three Extract stages of the 1-RTT key schedule (§7.1):

       early_secret     = HKDF-Extract(0, PSK)            (* PSK = 0 if none *)
       handshake_secret = HKDF-Extract(DeriveSecret(early_secret, "derived", ""),
                                       DHE)               (* DHE = 0 if none *)
       master_secret    = HKDF-Extract(DeriveSecret(handshake_secret, "derived", ""),
                                       0)

     `dhe` is the shared X25519 output (32 bytes); pass `zeros` for a PSK-only
     or no-PSK early phase. *)
  val earlySecret     : {psk : string} -> string
  val handshakeSecret : {earlySecret : string, dhe : string} -> string
  val masterSecret    : {handshakeSecret : string} -> string

  (* `derived` is the constant label used between Extract stages. *)
  val deriveLabel : string   (* "derived" *)

  (* Traffic-key expansion (§7.3 / §5.2):
       key = HkdfExpandLabel(secret, "key", "", keyLength)
       iv  = HkdfExpandLabel(secret, "iv",  "", ivLength)
     The caller picks `keyLength`/`ivLength` from the chosen AEAD algorithm
     (Aead.keyLen / Aead.nonceLen). *)
  val trafficKey : {secret : string, keyLength : int} -> string
  val trafficIv  : {secret : string, ivLength : int} -> string

  (* `finishedKey = HkdfExpandLabel(secret, "finished", "", Hash.length)`,
     used to compute the Finished verify_data. *)
  val finishedKey : {secret : string} -> string

  (* The full key schedule, bundling the three secrets together with the
     derived handshake-/application-traffic secrets. The handshake-traffic
     secrets are
       c_hs = DeriveSecret(handshake_secret, "c hs traffic", transcript)
       s_hs = DeriveSecret(handshake_secret, "s hs traffic", transcript)
     and the application-traffic secrets are
       c_ap = DeriveSecret(master_secret, "c ap traffic", transcript)
       s_ap = DeriveSecret(master_secret, "s ap traffic", transcript)
     where `transcript` is the *concatenated handshake messages* up to and
     including the ServerHello (for handshake-traffic) or up to the server
     Finished (for application-traffic). *)
  type keySchedule = {
    earlySecret       : string,
    handshakeSecret   : string,
    masterSecret      : string,
    clientHandshakeSecret : string,
    serverHandshakeSecret : string,
    clientAppSecret       : string,
    serverAppSecret       : string
  }

  (* Compute the full 1-RTT key schedule. `dhe` is the shared X25519 output;
     `clientHello` and `serverHello` are the *wire-form* handshake messages
     (as produced by `TlsHandshake.encodeMessage`), concatenated in order;
     `serverFinishedTranscript` is the transcript up to and including the
     server Finished (for application-traffic derivation). Pass empty strings
     for transcripts that are not yet available. *)
  val schedule : {dhe : string,
                  handshakeTranscript : string,
                  applicationTranscript : string} -> keySchedule

  (* The 64-byte "finished" input content string prefix used in
     CertificateVerify (§4.4.3): 64 space characters. *)
  val certificateVerifyPrefix : string

  (* Build the message that CertificateVerify signs / verifies:
       64 spaces ^ contextString ^ single space ^ transcriptHash
     `contextString` is "TLS 1.3, client CertificateVerify" or
     "TLS 1.3, server CertificateVerify". *)
  val certificateVerifyInput : {contextString : string, transcriptHash : string} -> string

  (* The two context strings. *)
  val clientCertVerifyContext : string  (* "TLS 1.3, client CertificateVerify" *)
  val serverCertVerifyContext : string  (* "TLS 1.3, server CertificateVerify" *)

  (* Compute the Finished verify_data:
       HMAC(finishedKey, Hash(transcript))
     using HMAC-SHA-256. `transcript` is the concatenated wire-form handshake
     messages up to and including the message just before this Finished. *)
  val finishedVerifyData : {finishedKey : string, transcript : string} -> string
end

signature TLS_CLIENT =
sig
  (* The opaque client state. The documented transitions are:

       Idle
         -- (caller invokes startHandshake with a ClientHello) -->
       ClientHelloSent
         -- (ServerHello received) -->
       ServerHelloReceived
         -- (EncryptedExtensions, Certificate, CertificateVerify, Finished) -->
       Connected

     See RFC 8446 §7.1 for the full 1-RTT client state machine. The state
     also carries the negotiated key schedule, traffic keys, and transcript
     once they are available. *)

  (* The extension type, shared with TLS_HANDSHAKE. The implementing
     structure must unify this with TlsHandshake.extension. *)
  type extension = {extType : Word16.word, data : string}

  type clientState

  (* The inputs the caller provides to drive the handshake: the client's
     X25519 private key, the chosen cipher suite, the client random, the
     legacy session id, and any extra ClientHello extensions. *)
  type clientConfig = {
    x25519PrivateKey  : string,        (* 32 bytes                     *)
    clientRandom      : string,        (* 32 bytes                     *)
    legacySessionId   : string,
    cipherSuites      : Word16.word list,
    extensions        : extension list
  }

  exception Tls of string

  (* Start a handshake: builds and encodes a ClientHello, returns the new
     state (ClientHelloSent) and the wire bytes to send (a single
     TLSPlaintext record containing the ClientHello handshake message). *)
  val startHandshake : clientConfig -> clientState * string

  (* Feed received bytes to the client. The bytes are a sequence of
     TLSPlaintext records (already decrypted by the caller's transport if
     they came after the ServerHello; this library does not itself perform
     record-layer decryption -- the caller does that using traffic keys
     extracted from the state via `trafficKeys`). Returns the updated state
     and the bytes to send (possibly empty). Raises `Tls` on a protocol
     violation. *)
  val step : clientState * string -> clientState * string list

  (* Inspect the state: the negotiated cipher suite, the current handshake
     traffic keys (for the caller to AEAD-protect/decrypt records), and the
     transcript-so-far. These are `option`s because they are only available
     after the ServerHello is processed. *)
  val negotiatedCipherSuite : clientState -> Word16.word option
  val serverHandshakeKey : clientState -> (string * string) option  (* (key, iv) *)
  val clientHandshakeKey : clientState -> (string * string) option
  val serverAppKey : clientState -> (string * string) option
  val clientAppKey : clientState -> (string * string) option
  val transcript : clientState -> string
  val isConnected : clientState -> bool
end

signature TLS_SERVER =
sig
  type extension = {extType : Word16.word, data : string}

  type serverState

  type serverConfig = {
    x25519PrivateKey  : string,        (* 32 bytes                     *)
    serverRandom      : string,        (* 32 bytes                     *)
    cipherSuite       : Word16.word,
    legacySessionId   : string,        (* echoed from ClientHello      *)
    extensions        : extension list
  }

  exception Tls of string

  (* Begin processing an incoming ClientHello. Returns the new state
     (ClientHelloReceived) and nothing to send yet; the caller then invokes
     `produceServerHello` to emit the ServerHello. *)
  val receiveClientHello : string -> serverState
      (* `string` is the ClientHello *body* (already extracted from its
         handshake header by the caller). *)

  val produceServerHello : serverState * serverConfig -> serverState * string

  (* Feed received bytes (already decrypted records) to the server. Returns
     the updated state and bytes to send. *)
  val step : serverState * string -> serverState * string list

  val negotiatedCipherSuite : serverState -> Word16.word option
  val serverHandshakeKey : serverState -> (string * string) option
  val clientHandshakeKey : serverState -> (string * string) option
  val serverAppKey : serverState -> (string * string) option
  val clientAppKey : serverState -> (string * string) option
  val transcript : serverState -> string
  val isConnected : serverState -> bool
end

signature TLS =
sig
  structure TlsRecord       : TLS_RECORD
  structure TlsAlert        : TLS_ALERT
  structure TlsHandshake    : TLS_HANDSHAKE
  structure TlsKeySchedule  : TLS_KEY_SCHEDULE
  structure TlsClient       : TLS_CLIENT
  structure TlsServer       : TLS_SERVER
end
