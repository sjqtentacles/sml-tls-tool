(* socket_shim.sml

   IMPURE / quarantined TCP driver around the pure sml-tls library.

   Philosophy mirrors sml-httpc-tool: keep ALL protocol logic in the pure
   core (sml-tls). This file only owns byte transport: open a socket,
   feed received bytes to `TlsClient.step` / `TlsServer.step`, send back
   the bytes the state machine returns. No protocol decisions here.

   The sml-tls library is sans-IO and pre-J1: the caller currently does
   record-layer decryption offboard. This shim accordingly treats the
   AEAD boundary as opaque and just passes raw record bytes to `step`.
   The shim is wired to compile and launch NOW; functional interop is
   the J2 gate (after J1 installs AEAD into the state machine). *)

structure SocketShim :> SOCKET_SHIM =
struct
  exception Shim of string

  (* string <-> Word8Vector for the socket API. sml-tls uses one char per
     byte, 0-255, matching the rest of the sjqtentacles family. *)
  fun toVec s =
    Word8Vector.tabulate (String.size s, fn i =>
      Word8.fromInt (Char.ord (String.sub (s, i))))

  fun fromVec v =
    CharVector.tabulate (Word8Vector.length v, fn i =>
      Char.chr (Word8.toInt (Word8Vector.sub (v, i))))

  fun resolve host =
    case NetHostDB.getByName host of
        SOME e => NetHostDB.addr e
      | NONE => raise Shim ("cannot resolve host: " ^ host)

  (* Read a whole file as a 1-char-per-byte string (for DER trust anchors). *)
  fun readFileBytes path =
    let
      val ins = BinIO.openIn path
      val v = BinIO.inputAll ins
      val () = BinIO.closeIn ins
    in
      CharVector.tabulate (Word8Vector.length v, fn i =>
        Char.chr (Word8.toInt (Word8Vector.sub (v, i))))
    end

  (* Optional differential config from the environment:
       TLS_TRUST_DER  path to a DER-encoded trust anchor (added to trustStore)
       TLS_SNI        SNI host_name / RFC 6125 match name override *)
  fun envTrustStore () =
    case OS.Process.getEnv "TLS_TRUST_DER" of
        NONE => []
      | SOME p => [readFileBytes p handle _ => raise Shim ("cannot read " ^ p)]

  (* Drain `toSend` to the socket, then loop receiving chunks and feeding
     them to `step`. `step` returns the new state and a list of byte
     strings to send back to the peer. We pump until either the state
     machine signals Connected or the peer closes the socket. *)
  fun pumpStep {sock, step, isConnected, toSend, state} =
    let
      (* Send any pending bytes the state machine produced. *)
      fun sendAll [] = ()
        | sendAll (b :: bs) =
            let val n = Socket.sendVec (sock, Word8VectorSlice.full (toVec b))
            in if Word8VectorSlice.length (Word8VectorSlice.full (toVec b)) = n
               then sendAll bs
               else raise Shim "short send" end
      val () = sendAll toSend
      (* Receive a chunk and feed it. *)
      val chunk = Socket.recvVec (sock, 65536)
    in
      if Word8Vector.length chunk = 0 then
        (if isConnected state then ()
         else raise Shim "peer closed before handshake completed")
      else
        let
          val (state', toSend') = step (state, fromVec chunk)
        in
          if isConnected state' then sendAll toSend'
          else pumpStep {sock = sock, step = step, isConnected = isConnected,
                         toSend = toSend', state = state'}
        end
    end

  fun clientHandshake {host, port, x25519PrivateKey, clientRandom,
                       legacySessionId, cipherSuites} =
    let
      val addr = INetSock.toAddr (resolve host, port)
      val sock = INetSock.TCP.socket ()
      val () = Socket.connect (sock, addr)
        handle e => (Socket.close sock; raise Shim ("connect failed: " ^ exnMessage e))
      val cfg : TlsClient.clientConfig = {
        x25519PrivateKey = x25519PrivateKey,
        p256PrivateKey   = NONE,
        clientRandom     = clientRandom,
        legacySessionId  = legacySessionId,
        cipherSuites     = cipherSuites,
        extensions       = [],
        serverName       = (case OS.Process.getEnv "TLS_SNI" of
                                SOME s => s | NONE => host),
        trustStore       = envTrustStore (),
        now              = (case Option.mapPartial Int.fromString
                                   (OS.Process.getEnv "TLS_NOW") of
                                SOME n => n | NONE => 0),
        sigAlgs          = [TlsHandshake.sigRsaPssRsaSha256]
      }
      val (st0, chBytes) = TlsClient.startHandshake cfg
        handle e => (Socket.close sock; raise Shim ("startHandshake: " ^ exnMessage e))
      val debug = OS.Process.getEnv "TLS_DEBUG" <> NONE
      fun dbg s = if debug then TextIO.output (TextIO.stdErr, s ^ "\n") else ()
      fun errStr st =
        case TlsClient.error st of
            NONE => "none" | SOME w => Word8.toString w
      fun sendAll [] = ()
        | sendAll (b :: bs) =
            (ignore (Socket.sendVec (sock, Word8VectorSlice.full (toVec b)));
             sendAll bs)
      (* Diagnostic, bounded pump: feed received chunks to TlsClient.step,
         reporting connect/error progress. Bounded so it always terminates. *)
      fun pump (state, toSend, iters) =
        if iters <= 0 then raise Shim "handshake did not converge (iteration cap)"
        else
          (sendAll toSend;
           if TlsClient.isConnected state then
             dbg "CONNECTED"
           else
             let val chunk = Socket.recvVec (sock, 65536)
             in
               if Word8Vector.length chunk = 0 then
                 (if TlsClient.isConnected state then dbg "CONNECTED"
                  else raise Shim ("peer closed; connected=false error="
                                   ^ errStr state))
               else
                 let val (state', toSend') = TlsClient.step (state, fromVec chunk)
                 in
                   dbg ("step: recv=" ^ Int.toString (Word8Vector.length chunk)
                        ^ " connected=" ^ Bool.toString (TlsClient.isConnected state')
                        ^ " error=" ^ errStr state'
                        ^ " toSend=" ^ Int.toString (List.length toSend'));
                   (case TlsClient.error state' of
                        SOME w => (sendAll toSend';
                                   raise Shim ("client error alert=" ^ Word8.toString w))
                      | NONE => pump (state', toSend', iters - 1))
                 end
             end)
    in
      (pump (st0, [chBytes], 16) handle e => (Socket.close sock; raise e))
      ; Socket.close sock
    end

  fun serverHandshake {port, x25519PrivateKey, serverRandom, cipherSuite} =
    let
      val listen = INetSock.TCP.socket ()
      val () = Socket.bind (listen, INetSock.any port)
      val () = Socket.listen (listen, 1)
      val (sock, _) = Socket.accept listen
        handle e => (Socket.close listen; raise Shim ("accept: " ^ exnMessage e))
      val () = Socket.close listen
      (* The server flow is: receive a TLSPlaintext record containing the
         ClientHello handshake message, parse out the handshake header
         to get the body, call receiveClientHello, then produceServerHello
         with the supplied config, then pump subsequent records through
         step. Until J1, step is a no-op; we still drive bytes for the
         differential harnesses. *)
      fun drive () =
        let
          val chunk = Socket.recvVec (sock, 65536)
        in
          if Word8Vector.length chunk = 0 then ()
          else
            let
              val s = fromVec chunk
              (* Decode the outer TLSPlaintext record. *)
              val recd =
                case TlsRecord.decodePlaintext s of
                    NONE => raise Shim "malformed record from client"
                  | SOME (r, _) => r
              val frag = #fragment recd
              (* Decode the handshake header to get the ClientHello body. *)
              val chBody =
                case TlsHandshake.decodeMessage frag of
                    NONE => raise Shim "malformed ClientHello"
                  | SOME ({msgType = TlsHandshake.ClientHello, body}, "") => body
                  | _ => raise Shim "expected ClientHello"
              val st0 = TlsServer.receiveClientHello chBody
              val cfg : TlsServer.serverConfig = {
                x25519PrivateKey = x25519PrivateKey,
                p256PrivateKey   = NONE,
                serverRandom     = serverRandom,
                cipherSuite      = cipherSuite,
                legacySessionId  = "",
                extensions       = [],
                certChain        = [],
                rsaPrivateKeyDer = "",
                sigAlg           = TlsHandshake.sigRsaPssRsaSha256,
                now              = 0,
                sigAlgs          = []
              }
              val (st1, shBytes) = TlsServer.produceServerHello (st0, cfg)
              val () = ignore (Socket.sendVec (sock, Word8VectorSlice.full (toVec shBytes)))
              (* Pump remaining bytes through step. *)
              fun loop st =
                let val c = Socket.recvVec (sock, 65536)
                in if Word8Vector.length c = 0 then ()
                   else
                     let val (st', toSend) = TlsServer.step (st, fromVec c)
                         fun sendAll [] = ()
                           | sendAll (b :: bs) =
                               (ignore (Socket.sendVec (sock, Word8VectorSlice.full (toVec b)));
                                sendAll bs)
                     in sendAll toSend; loop st' end
                end
            in loop st1 end
        end
    in
      (drive () handle e => (Socket.close sock; raise e))
      ; Socket.close sock
    end
end
