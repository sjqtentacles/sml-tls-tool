(* afl_harness.sml

   Shared infrastructure for AFL persistent-mode fuzz harnesses.

   Each per-decoder harness reads a chunk from stdin, calls the decoder,
   and exits 0 (so AFL treats any non-crashing run as "no bug"). Crashes
   (uncaught exceptions, infinite loops) are what AFL detects.

   In persistent mode (AFL_PERSISTENT env var set), we loop reading
   inputs from stdin until EOF; otherwise we process a single input.

   Convention: a decoder returns `NONE` on malformed input (per the
   sjqtentacles total-decoder discipline). The harness MUST NOT crash
   on `NONE`; it just continues. The bug class we hunt is uncaught
   exceptions (i.e. the decoder is not actually total). *)

structure AflHarness =
struct
  (* Read up to maxN bytes from TextIO.stdIn. Returns "" on EOF.
     We read one character at a time; AFL inputs are small. *)
  fun readStdinBytes maxN =
    let
      fun loop acc n =
        if n >= maxN then List.rev acc
        else
          (case TextIO.input1 TextIO.stdIn of
               NONE => List.rev acc
             | SOME c => loop (c :: acc) (n + 1))
      val chars = loop [] 0
    in
      CharVector.tabulate (List.length chars, fn i =>
        List.nth (chars, i))
    end

  (* Persistent loop: repeatedly read an input, run `decode`, until EOF.
     `decode` should not raise on malformed input; if it does, that is
     exactly the bug AFL wants to surface, and the process will crash. *)
  fun persistent decode =
    let
      val persistent = OS.Process.getEnv "AFL_PERSISTENT" <> NONE
      fun once () =
        let val s = readStdinBytes 65536
        in if String.size s = 0 then ()
           else (ignore (decode s); ()) end
      fun loop () =
        let val s = readStdinBytes 65536
        in if String.size s = 0 then ()
           else (ignore (decode s);
                 print ".";
                 loop ()) end
    in
      if persistent then loop () else once ()
    end

  fun run decode =
    (persistent decode; OS.Process.exit OS.Process.success)
end
