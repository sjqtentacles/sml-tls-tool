(* base16.sml *)

structure Base16 :> BASE16 =
struct
  fun nibble lower n =
    if n < 10 then Char.chr (Char.ord #"0" + n)
    else Char.chr ((if lower then Char.ord #"a" else Char.ord #"A") + (n - 10))

  fun encodeWith lower s =
    String.concat
      (List.map
        (fn c =>
          let val b = Char.ord c
          in String.implode [nibble lower (b div 16), nibble lower (b mod 16)] end)
        (String.explode s))

  fun encode s = encodeWith true s
  fun encodeUpper s = encodeWith false s

  fun hexVal c =
    if c >= #"0" andalso c <= #"9" then SOME (Char.ord c - Char.ord #"0")
    else if c >= #"a" andalso c <= #"f" then SOME (Char.ord c - Char.ord #"a" + 10)
    else if c >= #"A" andalso c <= #"F" then SOME (Char.ord c - Char.ord #"A" + 10)
    else NONE

  fun decode s =
    let
      val n = String.size s
    in
      if n mod 2 <> 0 then NONE
      else
        let
          fun loop i acc =
            if i >= n then SOME (String.implode (List.rev acc))
            else
              case (hexVal (String.sub (s, i)), hexVal (String.sub (s, i + 1))) of
                  (SOME hi, SOME lo) => loop (i + 2) (Char.chr (hi * 16 + lo) :: acc)
                | _ => NONE
        in
          loop 0 []
        end
    end
end
