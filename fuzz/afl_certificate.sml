(* afl_certificate.sml -- AFL persistent harness for TlsHandshake.decodeCertificate.

   Seed corpus: fuzz/corpus/certificate/*.bin (RFC 8448 Certificate bodies).

   Build:
     mlton -output bin/afl_certificate fuzz/afl_certificate.mlb
   Run:
     afl-fuzz -i fuzz/corpus/certificate -o out/certificate -- ./bin/afl_certificate
*)

val () = AflHarness.run TlsHandshake.decodeCertificate
