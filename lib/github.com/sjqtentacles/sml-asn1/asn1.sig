(* asn1.sig

   ASN.1 DER (Distinguished Encoding Rules) for the common subset, in pure
   Standard ML.

   DER is the canonical, length-prefixed binary form used by X.509
   certificates, PKCS, and most cryptographic on-the-wire formats.  Every
   value has exactly one valid encoding, so [encode] is a total function and
   [decode] is strict: it rejects anything that is not minimally encoded
   (redundant INTEGER leading bytes, long-form lengths that should be short,
   indefinite lengths, trailing garbage, ...).

   Arbitrary-precision INTEGER values are carried by the vendored
   [BigInt] structure (sml-bigint), so values far beyond the host [Int]
   range round-trip exactly.  Encoded values are plain [string]s of bytes
   (one byte per [char], codepoints 0..255), which keeps the library pure
   and identical across MLton and Poly/ML. *)

signature ASN1 =
sig
  (* The common subset of ASN.1 types.  [Context (n, d)] is an explicit
     context-specific tag [n] (0..30) wrapping an inner value [d]. *)
  datatype der =
      Bool of bool
    | Int of BigInt.int
    | Bytes of string            (* OCTET STRING *)
    | BitString of string        (* whole-octet bit string, 0 unused bits *)
    | Null
    | Oid of int list            (* object identifier arcs, >= 2 arcs *)
    | Utf8 of string             (* UTF8String *)
    | PrintableString of string
    | Seq of der list            (* SEQUENCE *)
    | Set of der list            (* SET *)
    | Context of int * der       (* explicit context-specific tag *)

  (* Raised by [encode] on an unrepresentable value (e.g. a bad OID) and by
     [decode] on any malformed / non-DER input. *)
  exception Asn1 of string

  (* DER-encode a value to its byte string.  Total on representable values. *)
  val encode : der -> string

  (* Decode a complete DER byte string; raises [Asn1] on malformed input or
     trailing bytes. *)
  val decode : string -> der

  (* As [decode], but returns NONE instead of raising. *)
  val decodeOpt : string -> der option
end
