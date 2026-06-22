(* socket_main.sml -- top-level entry for the socket shim.

   Usage:
     bin/socket_shim client HOST PORT
     bin/socket_shim server PORT

   Drives a single TLS handshake through the pure sml-tls state machine
   over a real TCP connection. The X25519 key and randoms are hardcoded
   to deterministic RFC-8448-style zeros for now; this is the foundation
   for differential testing and is expected to fail until J1/J2. *)

fun err s = (TextIO.output (TextIO.stdErr, s ^ "\n");
             OS.Process.exit OS.Process.failure)

val dummyKey = String.implode (List.tabulate (32, fn _ => #"\000"))
val dummyRnd = String.implode (List.tabulate (32, fn i => Char.chr (i mod 256)))

val () =
  case CommandLine.arguments () of
    ["client", host, portStr] =>
      (case Int.fromString portStr of
           SOME port =>
             (SocketShim.clientHandshake
                {host = host, port = port,
                 x25519PrivateKey = dummyKey, clientRandom = dummyRnd,
                 legacySessionId = "",
                 cipherSuites = [TlsHandshake.suiteTlsAes128GcmSha256]}
              handle e => err ("socket_shim: " ^ exnMessage e);
              OS.Process.exit OS.Process.success)
         | NONE => err "bad port")
  | ["server", portStr] =>
      (case Int.fromString portStr of
           SOME port =>
             (SocketShim.serverHandshake
                {port = port, x25519PrivateKey = dummyKey,
                 serverRandom = dummyRnd,
                 cipherSuite = TlsHandshake.suiteTlsAes128GcmSha256}
              handle e => err ("socket_shim: " ^ exnMessage e);
              OS.Process.exit OS.Process.success)
         | NONE => err "bad port")
  | _ => err "usage: socket_shim client HOST PORT | server PORT"
