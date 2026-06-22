(* token.sml *)

structure Token :> TOKEN =
struct
  fun sign key payload =
    let
      val mac = Hmac.hmacSha256 key payload
    in
      Base64.encodeUrl payload ^ "." ^ Base64.encodeUrl mac
    end

  fun verify key token =
    case String.fields (fn c => c = #".") token of
        [encPayload, encMac] =>
          (case (Base64.decode encPayload, Base64.decode encMac) of
               (SOME payload, SOME mac) =>
                 let val expected = Hmac.hmacSha256 key payload
                 in if Hmac.constantEq mac expected then SOME payload else NONE end
             | _ => NONE)
      | _ => NONE
end
