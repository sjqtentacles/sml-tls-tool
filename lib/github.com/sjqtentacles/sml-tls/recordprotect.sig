(* recordprotect.sig

   Record-layer AEAD protection for TLS 1.3 (RFC 8446 §5.2-5.3).

   This module owns per-direction traffic keys, the per-record nonce
   derivation (static IV XOR big-endian sequence number), sequence
   counters, content-type hiding + padding, and the 2^14 plaintext limit
   with `record_overflow` rejection. Moving AEAD protection *into* the
   library lets the state machine encrypt/decrypt internally instead of
   offloading it to the caller.

   This is the frozen contract for Track A1 (Phase 1). The Phase 0 stub
   raises `Fail "todo: A1"` from every function; the A1 subagent fills
   in the bodies against RFC 8448 vectors. *)

signature TLS_RECORD_PROTECT =
sig
  (* Opaque per-direction state: holds the traffic key, the static IV,
     and the monotonically-increasing 64-bit sequence counter. *)
  type state

  (* Initialise a fresh read/write direction from traffic key + IV. *)
  val init : {key : string, iv : string} -> state

  (* Per-record nonce = static IV XOR big-endian seq, left-padded to
     `Aead.nonceLen` (RFC 8446 §5.3). *)
  val nonce : {iv : string, seq : int} -> string

  (* 16384 = 2^14, the maximum TLSPlaintext fragment length (§5.1). *)
  val maxPlaintext : int

  (* Wrap an inner plaintext + content type into one TLSCiphertext
     record (§5.2): build TLSInnerPlaintext (plaintext || type || pad),
     AEAD-seal under (key, nonce, AAD=record header), and advance the
     sequence counter. Returns the ciphertext record body and the
     advanced state. `pad` is the number of trailing zero bytes of
     content-type hiding. *)
  val protect : {state    : state,
                 innerType : TlsRecord.contentType,
                 plaintext : string,
                 pad       : int} -> string * state

  (* Inverse of `protect`: AEAD-open the record, strip the padding,
     recover (innerType, plaintext), and advance the state. Returns
     NONE on AEAD authentication failure (caller maps to `bad_record_mac`)
     or on overflow. *)
  val unprotect : {state  : state,
                   record : string}
                  -> (TlsRecord.contentType * string * state) option
end
