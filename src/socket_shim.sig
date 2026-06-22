(* socket_shim.sig

   IMPURE / quarantined: real TCP sockets. This is the differential-testing
   transport for the pure sml-tls library; it owns NO protocol logic, only
   byte transport. Drives `TlsClient.step` / `TlsServer.step` over a real
   TCP connection.

   This is the foundation for all differential testing against real TLS
   endpoints (openssl s_server/s_client, tlsfuzzer, BoGo). *)

signature SOCKET_SHIM =
sig
  exception Shim of string

  (* Drive a TlsClient handshake against a remote TLS server at
     `host:port`. Sends the ClientHello produced by `startHandshake`,
     then pumps bytes between the socket and `TlsClient.step` until
     either the client reaches `Connected` or the peer closes.

     Returns the final transcript string on success, raises `Shim` on
     any transport or protocol failure.

     NOTE: until J1 wires AEAD into the state machine, the records the
     peer sends after ServerHello are AEAD-protected and `TlsClient.step`
     cannot decrypt them; the shim will still pump bytes but the client
     is expected to remain non-Connected. This is the J2 gate. *)
  val clientHandshake :
    { host : string, port : int,
      x25519PrivateKey : string,
      clientRandom : string,
      legacySessionId : string,
      cipherSuites : Word16.word list } -> unit

  (* Listen on `port`, accept one connection, and drive a TlsServer
     handshake against the connecting peer. Uses the supplied server
     config (key, random, cipher suite). Returns when the peer closes
     or the server reaches `Connected`. *)
  val serverHandshake :
    { port : int,
      x25519PrivateKey : string,
      serverRandom : string,
      cipherSuite : Word16.word } -> unit
end
