(* pem.sig

   PEM (RFC 7468) textual encoding of binary (DER) data over Base64.

   A PEM block is a Base64 body wrapped at 64 columns and framed by
   `-----BEGIN <label>-----` / `-----END <label>-----` lines, e.g.

     -----BEGIN CERTIFICATE-----
     MIICCjCCAXOgAwIBAgIUSLBZ...
     ...
     -----END CERTIFICATE-----

   Values (`der`) are raw byte strings: one byte per `char`, 0-255. The
   Base64 codec is supplied by the vendored `sml-codec`. Encoding is pure,
   total, and deterministic, and byte-identical under MLton and Poly/ML.

   Conventions:
   - `encode` emits LF line endings, the Base64 body wrapped at exactly 64
     columns (the final line may be shorter), with a trailing newline after
     the END line.
   - The `label` is taken verbatim (it may contain spaces, e.g.
     "RSA PRIVATE KEY").
   - `decode` extracts every well-formed block in document order. Explanatory
     text outside the BEGIN/END boundaries is ignored (per RFC 7468). Both
     CRLF and LF line endings are accepted.
   - `decode` raises `Pem` on a malformed block: a BEGIN with no matching END,
     a BEGIN/END label mismatch, a nested BEGIN, or a Base64 body that fails
     to decode. *)

signature PEM =
sig
  exception Pem of string

  val encode : {label:string, der:string} -> string
  val decode : string -> {label:string, der:string} list
end
