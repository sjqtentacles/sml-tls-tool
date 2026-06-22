(* afl_record.sml -- AFL persistent harness for TlsRecord.decodePlaintext.

   Seed corpus: fuzz/corpus/record/*.bin (RFC 8448 TLSPlaintext bytes).

   Build (see Makefile / README):
     mlton -output bin/afl_record fuzz/afl_record.mlb
   Run:
     afl-fuzz -i fuzz/corpus/record -o out/record -- ./bin/afl_record
*)

val () = AflHarness.run TlsRecord.decodePlaintext
