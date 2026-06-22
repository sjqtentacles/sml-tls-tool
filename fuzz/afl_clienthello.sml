(* afl_clienthello.sml -- AFL persistent harness for TlsHandshake.decodeClientHello.

   Seed corpus: fuzz/corpus/clienthello/*.bin (RFC 8448 ClientHello bodies).

   Build:
     mlton -output bin/afl_clienthello fuzz/afl_clienthello.mlb
   Run:
     afl-fuzz -i fuzz/corpus/clienthello -o out/clienthello -- ./bin/afl_clienthello
*)

val () = AflHarness.run TlsHandshake.decodeClientHello
