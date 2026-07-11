(* bogo_shim.sml

   BoGo (BoringSSL) test-runner shim for sml-tls.

   BoGo is a Go program that drives TLS implementations through a shim.
   The shim is a binary the runner spawns with `-shim-path`. The runner
   sends commands to the shim's stdin and reads responses from stdout:

     - The shim is invoked with command-line args describing the test:
         -server / -client   role
         -port N              TCP port to connect/accept on (loopback)
         -expect-handshake-success / -expect-.*-error   expected outcomes
         -min-version / -max-version  TLS version bounds
         -cipher ...          cipher selection
         ... many more; we recognise a starter subset and ignore the rest.
     - The shim performs the TLS handshake over a real TCP socket (the
       runner wires a loopback port).
     - On success, the shim exits 0; on failure, exits non-zero. Some
       tests assert specific outcomes via -expect-* flags.

   PORTING.md: https://boringssl.googlesource.com/boringssl/+/master/ssl/test/PORTING.md

   Status: starter subset. We implement the basic 1-RTT handshake test
   path (client and server) and parse a small subset of flags. This
   compiles NOW; actual handshake success is the J2 gate. *)

structure BogoShim :> BOGO_SHIM =
struct
  exception Shim of string

  (* Flag parsing is pure and lives in BogoArgs (see bogoargs.sig); this
     structure only drives the handshake and the stdio/exit-code contract. *)
  open BogoArgs

  (* ---- handshake driver ----

     The shim performs a real TCP handshake on the loopback port BoGo
     assigns. For -client: connect to that port. For -server: accept
     on it. The actual TLS handshake runs through the pure sml-tls
     state machine via SocketShim. *)
  fun doHandshake (a : args) =
    let
      val key = String.implode (List.tabulate (32, fn _ => #"\000"))
      val rnd = String.implode (List.tabulate (32, fn i => Char.chr (i mod 256)))
    in
      case #role a of
          Client =>
            SocketShim.clientHandshake
              {host = "127.0.0.1", port = #port a,
               x25519PrivateKey = key, clientRandom = rnd,
               legacySessionId = "",
               cipherSuites = [TlsHandshake.suiteTlsAes128GcmSha256]}
        | Server =>
            SocketShim.serverHandshake
              {port = #port a, x25519PrivateKey = key, serverRandom = rnd,
               cipherSuite = TlsHandshake.suiteTlsAes128GcmSha256}
    end

  fun main () =
    let
      val args = CommandLine.arguments ()
      val a = parseArgs args handle BadArg m =>
                (TextIO.output (TextIO.stdErr, "bogo-shim: " ^ m ^ "\n");
                 OS.Process.exit OS.Process.failure)
    in
      (doHandshake a;
       (* If the runner asked for handshake success, exit 0.
          If it asked for an error, the fact that we got here is a failure. *)
       if #expectError a <> NONE then
         (TextIO.output (TextIO.stdErr,
            "bogo-shim: expected error but handshake succeeded\n");
          OS.Process.exit OS.Process.failure)
       else OS.Process.exit OS.Process.success)
      handle e =>
        (TextIO.output (TextIO.stdErr,
           "bogo-shim: " ^ exnMessage e ^ "\n");
         (* If we expected an error, then a thrown exception is success. *)
         if #expectError a <> NONE then OS.Process.exit OS.Process.success
         else OS.Process.exit OS.Process.failure)
    end
end
