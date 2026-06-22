(* token.sig

   Signed tokens for cookies and CSRF. A payload string is signed with an
   HMAC-SHA256 keyed MAC and serialized as `payload.signature`, where both
   parts are URL-safe Base64. `verify` recomputes the MAC in constant time
   and returns the payload only if it matches, so tampered tokens are
   rejected. This provides integrity/authenticity, not confidentiality --
   the payload is readable (Base64), just not forgeable without the key. *)

signature TOKEN =
sig
  (* sign key payload -> "b64url(payload).b64url(mac)" *)
  val sign   : string -> string -> string
  (* verify key token -> SOME payload if the signature is valid, else NONE. *)
  val verify : string -> string -> string option
end
