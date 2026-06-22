(* asn1.sml

   ASN.1 DER (X.690) encoder/decoder for the common subset.

   Encoding is the canonical TLV form: an identifier octet (class /
   constructed bit / tag number), a DEFINITE length (short form < 128,
   otherwise long form with a minimal big-endian count), and the contents.
   INTEGER uses minimal two's-complement octets, OBJECT IDENTIFIER combines
   the first two arcs and base-128 encodes each subidentifier, and the
   arbitrary-precision INTEGER values are carried by the vendored BigInt.

   Decoding is strict: it rejects indefinite lengths, non-minimal lengths,
   non-minimal INTEGER / OID encodings, primitive types carrying the
   constructed bit, high-tag-number form, and any trailing bytes. *)

structure Asn1 :> ASN1 =
struct
  structure B = BigInt

  datatype der =
      Bool of bool
    | Int of B.int
    | Bytes of string
    | BitString of string
    | Null
    | Oid of int list
    | Utf8 of string
    | PrintableString of string
    | Seq of der list
    | Set of der list
    | Context of int * der

  exception Asn1 of string

  (* ---- universal tag numbers ---- *)
  val tBool   = 0x01
  val tInt    = 0x02
  val tBits   = 0x03
  val tOctet  = 0x04
  val tNull   = 0x05
  val tOid    = 0x06
  val tUtf8   = 0x0C
  val tSeq    = 0x10   (* encoded constructed: 0x30 *)
  val tSet    = 0x11   (* encoded constructed: 0x31 *)
  val tPrint  = 0x13

  val constructedBit = 0x20
  val contextClass   = 0x80

  (* one byte (codepoint 0..255) as a 1-char string *)
  fun chr n = String.str (Char.chr n)
  fun byteAt (s, i) = Char.ord (String.sub (s, i))

  (* ================= ENCODE ================= *)

  (* big-endian base-256 digits of a non-negative host int (>= 0) *)
  fun lenDigits n = if n = 0 then [] else lenDigits (n div 256) @ [n mod 256]

  fun encodeLen len =
    if len < 128 then chr len
    else
      let val ds = lenDigits len
      in chr (0x80 + List.length ds) ^ String.concat (List.map chr ds) end

  fun tlv (idByte, content) =
    chr idByte ^ encodeLen (String.size content) ^ content

  (* ---- INTEGER: minimal two's complement ---- *)
  val zero  = B.fromInt 0
  val two   = B.fromInt 2
  val b256  = B.fromInt 256

  (* little-endian base-256 digits of n >= 0 ([] for 0) *)
  fun digitsLE n =
    if B.compare (n, zero) = EQUAL then []
    else
      let val (q, r) = B.divMod (n, b256)
      in valOf (B.toInt r) :: digitsLE q end

  fun pow2 k = B.pow (two, B.fromInt k)

  fun encodeIntContent n =
    case B.compare (n, zero) of
      EQUAL => chr 0
    | GREATER =>
        let
          val be = List.rev (digitsLE n)
          val bytes = case be of
                        (hd :: _) => if hd >= 0x80 then 0 :: be else be
                      | [] => [0]
        in String.concat (List.map chr bytes) end
    | LESS =>
        let
          (* smallest k >= 1 with n >= ~(2^(8k-1)) *)
          fun findK k =
            if B.compare (n, B.~ (pow2 (8 * k - 1))) <> LESS then k
            else findK (k + 1)
          val k = findK 1
          val twos = B.add (pow2 (8 * k), n)        (* in [0, 2^(8k)) *)
          val be = List.rev (digitsLE twos)
          val pad = List.tabulate (k - List.length be, fn _ => 0)
        in String.concat (List.map chr (pad @ be)) end

  (* ---- OBJECT IDENTIFIER ---- *)

  (* base-128, big-endian, continuation bit on every byte but the last *)
  fun base128 v =
    let
      fun groupsLE n = if n < 128 then [n] else (n mod 128) :: groupsLE (n div 128)
      val be = List.rev (groupsLE v)
      val n = List.length be
      fun mark (_, []) = []
        | mark (i, x :: xs) = (if i < n - 1 then x + 0x80 else x) :: mark (i + 1, xs)
    in mark (0, be) end

  fun encodeOidContent arcs =
    case arcs of
      (a0 :: a1 :: rest) =>
        if a0 < 0 orelse a0 > 2 then raise Asn1 "OID: first arc must be 0, 1 or 2"
        else if a1 < 0 then raise Asn1 "OID: negative arc"
        else if a0 < 2 andalso a1 >= 40 then raise Asn1 "OID: second arc out of range"
        else if List.exists (fn x => x < 0) rest then raise Asn1 "OID: negative arc"
        else
          let val subs = (40 * a0 + a1) :: rest
          in String.concat (List.map chr (List.concat (List.map base128 subs))) end
    | _ => raise Asn1 "OID: needs at least two arcs"

  fun encode der =
    case der of
      Bool b => tlv (tBool, if b then chr 0xFF else chr 0x00)
    | Int n => tlv (tInt, encodeIntContent n)
    | Bytes s => tlv (tOctet, s)
    | BitString s => tlv (tBits, chr 0 ^ s)
    | Null => tlv (tNull, "")
    | Oid arcs => tlv (tOid, encodeOidContent arcs)
    | Utf8 s => tlv (tUtf8, s)
    | PrintableString s => tlv (tPrint, s)
    | Seq ds => tlv (tSeq + constructedBit, String.concat (List.map encode ds))
    | Set ds => tlv (tSet + constructedBit, String.concat (List.map encode ds))
    | Context (n, d) =>
        if n < 0 orelse n > 30 then raise Asn1 "Context: tag out of range (0..30)"
        else tlv (contextClass + constructedBit + n, encode d)

  (* ================= DECODE ================= *)

  (* read a DEFINITE length starting at [pos]; returns (length, posAfterLen) *)
  fun readLen (s, pos) =
    let
      val size = String.size s
      val () = if pos >= size then raise Asn1 "truncated length" else ()
      val b0 = byteAt (s, pos)
    in
      if b0 < 0x80 then (b0, pos + 1)
      else
        let val n = b0 - 0x80
        in
          if n = 0 then raise Asn1 "indefinite length not allowed in DER"
          else if pos + n >= size then raise Asn1 "truncated long-form length"
          else if byteAt (s, pos + 1) = 0 then raise Asn1 "non-minimal length (leading zero)"
          else
            let
              fun loop (i, acc) =
                if i = n then acc else loop (i + 1, acc * 256 + byteAt (s, pos + 1 + i))
              val len = loop (0, 0)
            in
              if len < 128 then raise Asn1 "non-minimal length (should be short form)"
              else (len, pos + 1 + n)
            end
        end
    end

  (* ---- INTEGER ---- *)
  fun decodeIntContent s =
    let
      val len = String.size s
      val () = if len = 0 then raise Asn1 "empty INTEGER" else ()
      val b0 = byteAt (s, 0)
      val () =
        if len > 1 then
          let val b1 = byteAt (s, 1)
          in
            if (b0 = 0x00 andalso b1 < 0x80) orelse (b0 = 0xFF andalso b1 >= 0x80)
            then raise Asn1 "non-minimal INTEGER" else ()
          end
        else ()
      fun fold (i, acc) =
        if i = len then acc
        else fold (i + 1, B.add (B.mul (acc, b256), B.fromInt (byteAt (s, i))))
      val mag = fold (0, zero)
    in
      if b0 >= 0x80 then B.sub (mag, pow2 (8 * len)) else mag
    end

  (* ---- OBJECT IDENTIFIER ---- *)
  fun decodeOidContent s =
    let
      val len = String.size s
      val () = if len = 0 then raise Asn1 "empty OID" else ()
      fun readSub (j, v, first) =
        if j = len then raise Asn1 "truncated OID subidentifier"
        else
          let
            val b = byteAt (s, j)
            val () = if first andalso b = 0x80 then raise Asn1 "non-minimal OID subidentifier" else ()
            val v' = v * 128 + (b mod 128)
          in
            if b < 0x80 then (v', j + 1) else readSub (j + 1, v', false)
          end
      fun loop (i, acc) =
        if i = len then List.rev acc
        else let val (v, next) = readSub (i, 0, true) in loop (next, v :: acc) end
      val subs = loop (0, [])
    in
      case subs of
        (first :: rest) =>
          let
            val (a0, a1) =
              if first < 40 then (0, first)
              else if first < 80 then (1, first - 40)
              else (2, first - 80)
          in a0 :: a1 :: rest end
      | [] => raise Asn1 "empty OID"
    end

  (* ---- BIT STRING ---- *)
  fun decodeBitString s =
    let
      val len = String.size s
      val () = if len = 0 then raise Asn1 "empty BIT STRING" else ()
      val unused = byteAt (s, 0)
      val () = if unused > 7 then raise Asn1 "BIT STRING: bad unused-bit count" else ()
    in
      String.extract (s, 1, NONE)
    end

  (* recursive descent over [s]; returns (value, posAfterValue) *)
  fun parseTLV (s, pos) =
    let
      val size = String.size s
      val () = if pos >= size then raise Asn1 "truncated identifier" else ()
      val id = byteAt (s, pos)
      val cls = id div 64                 (* top two bits: 0=universal, 2=context *)
      val constructed = (id div 32) mod 2 = 1
      val tagnum = id mod 32
      val () = if tagnum = 31 then raise Asn1 "high-tag-number form unsupported" else ()
      val (len, cstart) = readLen (s, pos + 1)
      val cend = cstart + len
      val () = if cend > size then raise Asn1 "length exceeds input" else ()
      val content = String.substring (s, cstart, len)
      fun prim () = if constructed then raise Asn1 "primitive type must not be constructed" else ()
    in
      case cls of
        0 (* universal *) =>
          if tagnum = tBool then
            ( prim ()
            ; if len <> 1 then raise Asn1 "BOOLEAN length"
              else case byteAt (content, 0) of
                     0x00 => (Bool false, cend)
                   | 0xFF => (Bool true, cend)
                   | _ => raise Asn1 "BOOLEAN value not 0x00/0xFF" )
          else if tagnum = tInt then (prim (); (Int (decodeIntContent content), cend))
          else if tagnum = tBits then (prim (); (BitString (decodeBitString content), cend))
          else if tagnum = tOctet then (prim (); (Bytes content, cend))
          else if tagnum = tNull then
            (prim (); if len <> 0 then raise Asn1 "NULL length" else (Null, cend))
          else if tagnum = tOid then (prim (); (Oid (decodeOidContent content), cend))
          else if tagnum = tUtf8 then (prim (); (Utf8 content, cend))
          else if tagnum = tPrint then (prim (); (PrintableString content, cend))
          else if tagnum = tSeq then
            if not constructed then raise Asn1 "SEQUENCE must be constructed"
            else (Seq (parseMany (s, cstart, cend)), cend)
          else if tagnum = tSet then
            if not constructed then raise Asn1 "SET must be constructed"
            else (Set (parseMany (s, cstart, cend)), cend)
          else raise Asn1 "unsupported universal tag"
      | 2 (* context-specific *) =>
          if not constructed then raise Asn1 "context tag must be constructed (explicit)"
          else
            let val (inner, ipos) = parseTLV (s, cstart)
            in
              if ipos <> cend then raise Asn1 "context content is not a single TLV"
              else (Context (tagnum, inner), cend)
            end
      | _ => raise Asn1 "unsupported tag class"
    end
  and parseMany (s, pos, stop) =
    if pos = stop then []
    else if pos > stop then raise Asn1 "element overruns its container"
    else let val (d, pos') = parseTLV (s, pos) in d :: parseMany (s, pos', stop) end

  fun decode s =
    let val (d, pos) = parseTLV (s, 0)
    in if pos <> String.size s then raise Asn1 "trailing bytes after value" else d end

  fun decodeOpt s = SOME (decode s) handle _ => NONE
end
