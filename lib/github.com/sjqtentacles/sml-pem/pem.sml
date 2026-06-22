(* pem.sml

   PEM (RFC 7468) encode/decode over Base64 (from the vendored sml-codec). *)

structure Pem :> PEM =
struct
  exception Pem of string

  val beginPre = "-----BEGIN "
  val endPre   = "-----END "
  val suffix   = "-----"
  val newline  = "\n"

  (* Split a Base64 string into chunks of at most 64 columns. *)
  fun chunk64 s =
    let
      val n = String.size s
      fun go i acc =
        if i >= n then List.rev acc
        else
          let val len = if n - i < 64 then n - i else 64
          in go (i + len) (String.substring (s, i, len) :: acc) end
    in
      go 0 []
    end

  fun encode {label, der} =
    let
      val body = chunk64 (Base64.encode der)
      val lines =
        (beginPre ^ label ^ suffix) :: body @ [endPre ^ label ^ suffix]
    in
      String.concat (List.map (fn l => l ^ newline) lines)
    end

  (* A boundary line is `<pre><label><suffix>`; return the label if it
     matches, else NONE. *)
  fun boundaryLabel pre line =
    let
      val plen = String.size pre
      val slen = String.size suffix
    in
      if String.size line >= plen + slen
         andalso String.isPrefix pre line
         andalso String.isSuffix suffix line
      then SOME (String.substring (line, plen, String.size line - plen - slen))
      else NONE
    end

  val beginLabel = boundaryLabel beginPre
  val endLabel   = boundaryLabel endPre

  (* Strip a single trailing CR so CRLF documents behave like LF ones. *)
  fun stripCR l =
    let val n = String.size l in
      if n > 0 andalso String.sub (l, n - 1) = #"\r"
      then String.substring (l, 0, n - 1)
      else l
    end

  fun decode input =
    let
      val lines = List.map stripCR (String.fields (fn c => c = #"\n") input)

      fun finishBlock label body =
        case Base64.decode (String.concat (List.rev body)) of
            SOME der => {label = label, der = der}
          | NONE => raise Pem ("invalid Base64 body in block " ^ label)

      (* Inside a block: accumulate body lines until the matching END. *)
      fun collect label body [] =
            raise Pem ("BEGIN " ^ label ^ " without matching END")
        | collect label body (l :: rest) =
            (case endLabel l of
                 SOME other =>
                   if other = label
                   then finishBlock label body :: scan rest
                   else raise Pem ("END label mismatch: BEGIN " ^ label ^
                                   " vs END " ^ other)
               | NONE =>
                   (case beginLabel l of
                        SOME _ => raise Pem ("nested BEGIN inside block " ^ label)
                      | NONE => collect label (l :: body) rest))

      (* Outside any block: skip explanatory text until the next BEGIN. *)
      and scan [] = []
        | scan (l :: rest) =
            (case beginLabel l of
                 SOME label => collect label [] rest
               | NONE => scan rest)
    in
      scan lines
    end
end
