(* test.sml -- sml-tls-tool.
 *
 * This is an IMPURE, quarantined harness repo (real sockets, subprocesses,
 * AFL stdin) -- see README.md. Its only genuinely pure, deterministic
 * surface is the transport-adjacent parsing it owns: byte<->vector
 * conversion (ByteVec) and BoGo command-line flag parsing (BogoArgs). Both
 * are exercised here exhaustively; the TLS protocol logic itself is tested
 * in the pure sml-tls core. *)

structure Tests =
struct
  open Harness

  fun runByteVec () =
    let
      val () = section "ByteVec: round-trip"
      val () = check "empty string round-trips"
        (ByteVec.fromVec (ByteVec.toVec "") = "")
      val () = check "ASCII string round-trips"
        (ByteVec.fromVec (ByteVec.toVec "hello, TLS") = "hello, TLS")
      (* All 256 byte values in one string, exercising both directions. *)
      val allBytes = String.implode (List.tabulate (256, Char.chr))
      val () = check "all 256 byte values round-trip"
        (ByteVec.fromVec (ByteVec.toVec allBytes) = allBytes)

      val () = section "ByteVec: explicit encoding"
      val () = checkInt "toVec length matches string size"
        (5, Word8Vector.length (ByteVec.toVec "abcde"))
      val () = check "toVec \"AB\" = [0x41, 0x42]"
        (ByteVec.toVec "AB" = Word8Vector.fromList [0wx41, 0wx42])
      val () = check "toVec of NUL/high byte"
        (ByteVec.toVec "\000\255" = Word8Vector.fromList [0wx00, 0wxFF])
      val () = check "fromVec [0x41, 0x42] = \"AB\""
        (ByteVec.fromVec (Word8Vector.fromList [0wx41, 0wx42]) = "AB")
      val () = check "fromVec empty vector = empty string"
        (ByteVec.fromVec (Word8Vector.fromList []) = "")
    in () end

  fun runParseVersion () =
    let
      val () = section "BogoArgs.parseVersion"
      val () = check "TLS1.3 -> 0x0304"
        (BogoArgs.parseVersion "TLS1.3" = 0wx0304)
      val () = check "TLS1.2 -> 0x0303"
        (BogoArgs.parseVersion "TLS1.2" = 0wx0303)
      val () = check "TLS1.1 -> 0x0302"
        (BogoArgs.parseVersion "TLS1.1" = 0wx0302)
      val () = check "TLS1 -> 0x0301"
        (BogoArgs.parseVersion "TLS1" = 0wx0301)
      val () = checkRaises "unknown version string raises BadArg"
        (fn () => BogoArgs.parseVersion "SSL3.0")
      val () = checkRaises "empty version string raises BadArg"
        (fn () => BogoArgs.parseVersion "")
    in () end

  fun runParseArgs () =
    let
      val () = section "BogoArgs.parseArgs: defaults"
      val d = BogoArgs.parseArgs []
      val () = check "default role is Client"
        (#role d = BogoArgs.Client)
      val () = checkInt "default port is 0" (0, #port d)
      val () = check "default minVersion is NONE" (#minVersion d = NONE)
      val () = check "default expectHandshakeSuccess is false"
        (not (#expectHandshakeSuccess d))
      val () = check "default rest is []" (#rest d = [])

      val () = section "BogoArgs.parseArgs: role"
      val () = check "-server sets role Server"
        (#role (BogoArgs.parseArgs ["-server"]) = BogoArgs.Server)
      val () = check "-client sets role Client"
        (#role (BogoArgs.parseArgs ["-client"]) = BogoArgs.Client)
      val () = check "later role flag wins over earlier"
        (#role (BogoArgs.parseArgs ["-server", "-client"]) = BogoArgs.Client)

      val () = section "BogoArgs.parseArgs: -port"
      val () = checkInt "-port 4433 sets port"
        (4433, #port (BogoArgs.parseArgs ["-port", "4433"]))
      val () = checkInt "-port 0 is accepted"
        (0, #port (BogoArgs.parseArgs ["-port", "0"]))
      val () = checkInt "-port at the 32-bit boundary (2147483647) is accepted"
        (2147483647, #port (BogoArgs.parseArgs ["-port", "2147483647"]))
      val () = checkRaises "-port one past the 32-bit boundary raises BadArg"
        (fn () => BogoArgs.parseArgs ["-port", "2147483648"])
      val () = checkRaises "-port negative raises BadArg"
        (fn () => BogoArgs.parseArgs ["-port", "-1"])
      val () = checkRaises "-port non-numeric raises BadArg"
        (fn () => BogoArgs.parseArgs ["-port", "not-a-port"])

      val () = section "BogoArgs.parseArgs: versions"
      val v1 = BogoArgs.parseArgs ["-min-version", "TLS1.2", "-max-version", "TLS1.3"]
      val () = check "-min-version wires to parseVersion"
        (#minVersion v1 = SOME 0wx0303)
      val () = check "-max-version wires to parseVersion"
        (#maxVersion v1 = SOME 0wx0304)
      val () = checkRaises "-min-version with a bad version string raises BadArg"
        (fn () => BogoArgs.parseArgs ["-min-version", "bogus"])

      val () = section "BogoArgs.parseArgs: expectations"
      val () = check "-expect-handshake-success sets the flag"
        (#expectHandshakeSuccess (BogoArgs.parseArgs ["-expect-handshake-success"]))
      val v2 = BogoArgs.parseArgs ["-expect-.*-error", "alert=40"]
      val () = check "-expect-.*-error captures its value"
        (#expectError v2 = SOME "alert=40")
      val v3 = BogoArgs.parseArgs ["-expect-msg", "hello"]
      val () = check "-expect-msg captures its value"
        (#expectMsg v3 = SOME "hello")

      val () = section "BogoArgs.parseArgs: unrecognised flags"
      val v4 = BogoArgs.parseArgs ["-cipher", "TLS_AES_128_GCM_SHA256"]
      val () = check "unknown flag and its value are both stashed into rest"
        (#rest v4 = ["TLS_AES_128_GCM_SHA256", "-cipher"])
      val () = check "a bare unknown flag alone is stashed"
        (#rest (BogoArgs.parseArgs ["-shim-writes-first"]) = ["-shim-writes-first"])

      val () = section "BogoArgs.parseArgs: a realistic full BoGo invocation"
      val full = BogoArgs.parseArgs
        ["-server", "-port", "34567", "-min-version", "TLS1.3",
         "-max-version", "TLS1.3", "-expect-handshake-success",
         "-cipher", "TLS_AES_128_GCM_SHA256"]
      val () = check "role" (#role full = BogoArgs.Server)
      val () = checkInt "port" (34567, #port full)
      val () = check "minVersion" (#minVersion full = SOME 0wx0304)
      val () = check "maxVersion" (#maxVersion full = SOME 0wx0304)
      val () = check "expectHandshakeSuccess" (#expectHandshakeSuccess full)
      val () = check "unrecognised -cipher + value stashed, in encounter order reversed"
        (#rest full = ["TLS_AES_128_GCM_SHA256", "-cipher"])
    in () end

  fun run () =
    ( runByteVec ()
    ; runParseVersion ()
    ; runParseArgs ()
    ; Harness.run ()
    )
end
