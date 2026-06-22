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

  (* ---- arg parsing ---- *)
  datatype role = Client | Server
  type args = {
    role : role,
    port : int,
    minVersion : Word16.word option,
    maxVersion : Word16.word option,
    expectHandshakeSuccess : bool,
    expectError : string option,
    expectMsg : string option,
    rest : string list
  }

  val defaultArgs = {
    role = Client,
    port = 0,
    minVersion = NONE,
    maxVersion = NONE,
    expectHandshakeSuccess = false,
    expectError = NONE,
    expectMsg = NONE,
    rest = []
  }

  fun setRole a r = {role = r, port = #port a, minVersion = #minVersion a,
                     maxVersion = #maxVersion a,
                     expectHandshakeSuccess = #expectHandshakeSuccess a,
                     expectError = #expectError a,
                     expectMsg = #expectMsg a, rest = #rest a}
  fun setPort a p = {role = #role a, port = p, minVersion = #minVersion a,
                     maxVersion = #maxVersion a,
                     expectHandshakeSuccess = #expectHandshakeSuccess a,
                     expectError = #expectError a,
                     expectMsg = #expectMsg a, rest = #rest a}
  fun setMin a v = {role = #role a, port = #port a, minVersion = SOME v,
                    maxVersion = #maxVersion a,
                    expectHandshakeSuccess = #expectHandshakeSuccess a,
                    expectError = #expectError a,
                    expectMsg = #expectMsg a, rest = #rest a}
  fun setMax a v = {role = #role a, port = #port a, minVersion = #minVersion a,
                    maxVersion = SOME v,
                    expectHandshakeSuccess = #expectHandshakeSuccess a,
                    expectError = #expectError a,
                    expectMsg = #expectMsg a, rest = #rest a}
  fun setHS a = {role = #role a, port = #port a, minVersion = #minVersion a,
                 maxVersion = #maxVersion a,
                 expectHandshakeSuccess = true,
                 expectError = #expectError a,
                 expectMsg = #expectMsg a, rest = #rest a}
  fun setErr a e = {role = #role a, port = #port a, minVersion = #minVersion a,
                    maxVersion = #maxVersion a,
                    expectHandshakeSuccess = #expectHandshakeSuccess a,
                    expectError = SOME e,
                    expectMsg = #expectMsg a, rest = #rest a}
  fun setMsg a m = {role = #role a, port = #port a, minVersion = #minVersion a,
                    maxVersion = #maxVersion a,
                    expectHandshakeSuccess = #expectHandshakeSuccess a,
                    expectError = #expectError a,
                    expectMsg = SOME m, rest = #rest a}
  fun pushRest a s = {role = #role a, port = #port a, minVersion = #minVersion a,
                      maxVersion = #maxVersion a,
                      expectHandshakeSuccess = #expectHandshakeSuccess a,
                      expectError = #expectError a,
                      expectMsg = #expectMsg a, rest = s :: #rest a}

  fun parseArgs args =
    let
      fun go [] a = a
        | go ("-server" :: rest) a = go rest (setRole a Server)
        | go ("-client" :: rest) a = go rest (setRole a Client)
        | go ("-port" :: p :: rest) a =
            (case Int.fromString p of
                 SOME n => go rest (setPort a n)
               | NONE => raise Shim ("bad -port: " ^ p))
        | go ("-min-version" :: v :: rest) a =
            go rest (setMin a (parseVersion v))
        | go ("-max-version" :: v :: rest) a =
            go rest (setMax a (parseVersion v))
        | go ("-expect-handshake-success" :: rest) a = go rest (setHS a)
        | go ("-expect-.*-error" :: v :: rest) a = go rest (setErr a v)
        | go ("-expect-msg" :: v :: rest) a = go rest (setMsg a v)
        | go (flag :: rest) a =
            if String.isPrefix "-" flag andalso String.size flag > 1
            then go rest (pushRest a flag)  (* skip unknown flag, stash it *)
            else go rest (pushRest a flag)
    in go args defaultArgs end

  (* Map BoGo version strings to the TLS 1.3 version word (0x0304).
     BoGo uses "TLS1", "TLS1.1", "TLS1.2", "TLS1.3" -- we only care
     about 1.3 today; older values are accepted and clamped to 0x0303. *)
  and parseVersion "TLS1.3" = 0wx0304
    | parseVersion "TLS1.2" = 0wx0303
    | parseVersion "TLS1.1" = 0wx0302
    | parseVersion "TLS1"   = 0wx0301
    | parseVersion v        = raise Shim ("unknown version: " ^ v)

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
      val a = parseArgs args handle Shim m =>
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
