(* base64.sml *)

structure Base64 :> BASE64 =
struct
  val stdAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  val urlAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

  fun encodeWith alpha pad s =
    let
      val a = Vector.fromList (String.explode alpha)
      fun ch i = Vector.sub (a, i)
      val bytes = String.explode s
      fun go cs acc =
        case cs of
            [] => List.rev acc
          | [c0] =>
              let
                val b0 = Char.ord c0
                val e0 = ch (b0 div 4)
                val e1 = ch ((b0 mod 4) * 16)
              in
                List.rev (if pad then #"=" :: #"=" :: e1 :: e0 :: acc
                          else e1 :: e0 :: acc)
              end
          | [c0, c1] =>
              let
                val b0 = Char.ord c0 and b1 = Char.ord c1
                val e0 = ch (b0 div 4)
                val e1 = ch ((b0 mod 4) * 16 + b1 div 16)
                val e2 = ch ((b1 mod 16) * 4)
              in
                List.rev (if pad then #"=" :: e2 :: e1 :: e0 :: acc
                          else e2 :: e1 :: e0 :: acc)
              end
          | c0 :: c1 :: c2 :: rest =>
              let
                val b0 = Char.ord c0 and b1 = Char.ord c1 and b2 = Char.ord c2
                val e0 = ch (b0 div 4)
                val e1 = ch ((b0 mod 4) * 16 + b1 div 16)
                val e2 = ch ((b1 mod 16) * 4 + b2 div 64)
                val e3 = ch (b2 mod 64)
              in
                go rest (e3 :: e2 :: e1 :: e0 :: acc)
              end
    in
      String.implode (go bytes [])
    end

  fun encode s = encodeWith stdAlpha true s
  fun encodeUrl s = encodeWith urlAlpha false s

  fun deval c =
    if c >= #"A" andalso c <= #"Z" then SOME (Char.ord c - Char.ord #"A")
    else if c >= #"a" andalso c <= #"z" then SOME (Char.ord c - Char.ord #"a" + 26)
    else if c >= #"0" andalso c <= #"9" then SOME (Char.ord c - Char.ord #"0" + 52)
    else if c = #"+" orelse c = #"-" then SOME 62
    else if c = #"/" orelse c = #"_" then SOME 63
    else NONE

  fun decode s =
    let
      (* Drop padding; collect 6-bit values, rejecting strays. *)
      val raw = List.filter (fn c => c <> #"=") (String.explode s)
      fun collect cs acc =
        case cs of
            [] => SOME (List.rev acc)
          | c :: rest =>
              (case deval c of SOME v => collect rest (v :: acc) | NONE => NONE)
    in
      case collect raw [] of
          NONE => NONE
        | SOME vals =>
            let
              fun go vs acc =
                case vs of
                    [] => SOME (List.rev acc)
                  | [_] => NONE  (* a lone 6-bit group cannot exist *)
                  | [v0, v1] =>
                      let val b0 = v0 * 4 + v1 div 16
                      in SOME (List.rev (Char.chr b0 :: acc)) end
                  | [v0, v1, v2] =>
                      let
                        val b0 = v0 * 4 + v1 div 16
                        val b1 = (v1 mod 16) * 16 + v2 div 4
                      in SOME (List.rev (Char.chr b1 :: Char.chr b0 :: acc)) end
                  | v0 :: v1 :: v2 :: v3 :: rest =>
                      let
                        val b0 = v0 * 4 + v1 div 16
                        val b1 = (v1 mod 16) * 16 + v2 div 4
                        val b2 = (v2 mod 4) * 64 + v3
                      in go rest (Char.chr b2 :: Char.chr b1 :: Char.chr b0 :: acc) end
            in
              case go vals [] of
                  SOME cs => SOME (String.implode cs)
                | NONE => NONE
            end
    end
end
