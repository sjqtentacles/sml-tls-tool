(* afl_ciphertext.sml -- AFL persistent harness for TlsRecord.decodeCiphertext.

   Seed corpus: fuzz/corpus/ciphertext/*.bin.

   Build:
     mlton -output bin/afl_ciphertext fuzz/afl_ciphertext.mlb
   Run:
     afl-fuzz -i fuzz/corpus/ciphertext -o out/ciphertext -- ./bin/afl_ciphertext
*)

val () = AflHarness.run TlsRecord.decodeCiphertext
