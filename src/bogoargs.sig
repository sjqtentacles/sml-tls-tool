(* bogoargs.sig

   Pure parsing of the BoGo (BoringSSL test-runner) shim command-line flags.
   BoGo invokes the shim binary with flags like `-server -port 1234
   -expect-handshake-success`; this module owns only that parsing, no I/O.
   See PORTING.md: https://boringssl.googlesource.com/boringssl/+/master/ssl/test/PORTING.md *)

signature BOGO_ARGS =
sig
  exception BadArg of string

  datatype role = Client | Server

  type args = {
    role : role,
    port : int,
    minVersion : Word16.word option,
    maxVersion : Word16.word option,
    expectHandshakeSuccess : bool,
    expectError : string option,
    expectMsg : string option,
    rest : string list          (* unrecognised flags, in reverse order *)
  }

  val defaultArgs : args

  (* Parse a full argv (as from CommandLine.arguments ()) into an args
     record. Raises BadArg on a malformed -port or unknown -*-version. An
     unrecognised flag (and any following bare token) is not an error -- it
     is stashed into `rest`, since BoGo passes many flags this shim does not
     yet act on. *)
  val parseArgs : string list -> args

  (* Map a BoGo version string ("TLS1".."TLS1.3") to the two-byte TLS
     version word. Raises BadArg on an unrecognised string. *)
  val parseVersion : string -> Word16.word
end
