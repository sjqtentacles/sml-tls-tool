(* afl_recordprotect.sml -- AFL persistent harness for TlsRecordProtect.unprotect.

   Fuzzes the AEAD-open path with a fixed dummy state. The state's key
   and IV are 16/12 zero bytes (AES-128-GCM); the fuzzer varies the
   ciphertext-record bytes. Successful authentication is rare and is
   not the bug class: we are hunting for crashes (uncaught exceptions
   in the padding-strip / sequence-advance / overflow-reject paths).

   Seed corpus: fuzz/corpus/recordprotect/*.bin (RFC 8448 encrypted
   records, which WILL authenticate against the RFC 8448 traffic key;
   use a corpus-from-RFC-8448 setup at J2 to seed real positives).

   Build:
     mlton -output bin/afl_recordprotect fuzz/afl_recordprotect.mlb
   Run:
     AFL_PERSISTENT=1 afl-fuzz -i fuzz/corpus/recordprotect \
       -o out/recordprotect -- ./bin/afl_recordprotect

   NOTE: until A1 lands, TlsRecordProtect is a Phase 0 stub that raises
   Fail "todo: A1" from `unprotect`. This harness will therefore crash
   on every input; AFL surfaces that to the J2 fixers. Compiles today.
*)

val dummyState =
  TlsRecordProtect.init
    {key = String.implode (List.tabulate (16, fn _ => #"\000")),
     iv  = String.implode (List.tabulate (12, fn _ => #"\000"))}

fun decode s =
  TlsRecordProtect.unprotect {state = dummyState, record = s}

val () = AflHarness.run decode
