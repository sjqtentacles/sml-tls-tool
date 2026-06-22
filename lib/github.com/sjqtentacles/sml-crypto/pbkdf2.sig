(* pbkdf2.sig

   PBKDF2 (RFC 2898 / RFC 8018) with HMAC-SHA-256 and HMAC-SHA-512 as the
   underlying PRF. Returns the raw derived key of the requested length. *)

signature PBKDF2 =
sig
  val pbkdf2Sha256 : {password:string, salt:string, iters:int, dkLen:int} -> string
  val pbkdf2Sha512 : {password:string, salt:string, iters:int, dkLen:int} -> string
end
