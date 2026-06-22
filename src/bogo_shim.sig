(* bogo_shim.sig

   BoringSSL BoGo shim protocol implementation for sml-tls.

   BoGo (BoringSSL's Go-based test runner) drives TLS implementations
   through a simple line-based stdio protocol: the runner spawns the
   shim binary, sends commands on stdin, reads responses on stdout.
   Each line is a key=value pair or a bare command. See:

     https://boringssl.googlesource.com/boringssl/+/master/ssl/test/PORTING.md

   This is the IMPURE quarantined harness. It owns NO protocol logic
   beyond the BoGo wire protocol itself; all TLS is delegated to the
   pure sml-tls library. *)

signature BOGO_SHIM =
sig
  (* Run the BoGo shim main loop: read commands from stdin, write
     responses to stdout, exit 0 on success / non-zero on failure.
     Intended to be invoked as `main ()` from a top-level program. *)
  val main : unit -> unit
end
