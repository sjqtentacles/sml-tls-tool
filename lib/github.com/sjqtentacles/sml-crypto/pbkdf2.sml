(* pbkdf2.sml

   PBKDF2 (RFC 2898 / RFC 8018). For each output block i,
     T_i = U_1 xor U_2 xor ... xor U_c   where
     U_1 = PRF(password, salt || INT_32_BE(i)) and U_j = PRF(password, U_{j-1}).
   The derived key is T_1 || T_2 || ... truncated to dkLen bytes. *)

structure Pbkdf2 :> PBKDF2 =
struct
  fun xorStr (a : string, b : string) : string =
    String.implode (List.tabulate (String.size a, fn i =>
      Char.chr (Word.toInt (Word.xorb
        (Word.fromInt (Char.ord (String.sub (a, i))),
         Word.fromInt (Char.ord (String.sub (b, i))))))))

  fun int32be (i : int) : string =
    String.implode (List.tabulate (4, fn k =>
      Char.chr (Word.toInt (Word.andb
        (Word.>> (Word.fromInt i, Word.fromInt (24 - k*8)), 0wxff)))))

  (* prf is the keyed PRF (HMAC key message); hLen its output size. *)
  fun derive (prf : string -> string -> string) (hLen : int)
             {password:string, salt:string, iters:int, dkLen:int} : string =
    let
      val nBlocks = (dkLen + hLen - 1) div hLen

      fun block (i : int) : string =
        let
          val u1 = prf password (salt ^ int32be i)
          fun loop (j : int, prev : string, acc : string) : string =
            if j > iters then acc
            else
              let val cur = prf password prev
              in loop (j + 1, cur, xorStr (acc, cur)) end
        in
          loop (2, u1, u1)
        end

      val full = String.concat (List.tabulate (nBlocks, fn i => block (i + 1)))
    in
      String.substring (full, 0, dkLen)
    end

  fun pbkdf2Sha256 args = derive Hmac.hmacSha256 32 args
  fun pbkdf2Sha512 args = derive Hmac.hmacSha512 64 args
end
