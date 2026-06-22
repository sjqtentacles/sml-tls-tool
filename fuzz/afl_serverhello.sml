(* afl_serverhello.sml -- AFL persistent harness for TlsHandshake.decodeServerHello.

   Seed corpus: fuzz/corpus/serverhello/*.bin (RFC 8448 ServerHello bodies).

   Build:
     mlton -output bin/afl_serverhello fuzz/afl_serverhello.mlb
   Run:
     afl-fuzz -i fuzz/corpus/serverhello -o out/serverhello -- ./bin/afl_serverhello
*)

val () = AflHarness.run TlsHandshake.decodeServerHello
