(* afl_extensions.sml -- AFL persistent harness for TlsExtensions decoders.

   Each of the TlsExtensions decoders accepts a string and returns an
   option. We cycle through them so AFL can fuzz all extension bodies
   from one binary; alternatively, build per-decoder harnesses by
   selecting the function you want below.

   Seed corpus: fuzz/corpus/extensions/*.bin (RFC 8448 extension bodies).

   Build:
     mlton -output bin/afl_extensions fuzz/afl_extensions.mlb
   Run:
     afl-fuzz -i fuzz/corpus/extensions -o out/extensions -- ./bin/afl_extensions

   NOTE: until A3 lands, TlsExtensions is a Phase 0 stub that raises
   Fail "todo: A3" from every decoder. This harness will therefore
   crash on every input, which is exactly what AFL should surface to
   the J2 fixer agents. The harness compiles against the stub today.
*)

fun decodeAll s =
  let
    val _ = TlsExtensions.decodeKeyShareCH s
    val _ = TlsExtensions.decodeKeyShareSH s
    val _ = TlsExtensions.decodeSupportedGroups s
    val _ = TlsExtensions.decodeSignatureAlgorithms s
    val _ = TlsExtensions.decodeServerName s
    val _ = TlsExtensions.decodeAlpn s
  in NONE end

val () = AflHarness.run decodeAll
