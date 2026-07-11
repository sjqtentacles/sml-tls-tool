(* bytevec.sig

   Pure string <-> Word8Vector.vector conversion shared by the socket and
   BoGo shims. sml-tls (like the rest of the sjqtentacles family) represents
   byte strings as one-char-per-byte SML strings (0-255); the socket API
   needs Word8Vector.vector. This conversion has no I/O of its own -- it is
   the one piece of the transport layer that is genuinely pure and testable
   without opening a real socket. *)

signature BYTE_VEC =
sig
  val toVec   : string -> Word8Vector.vector
  val fromVec : Word8Vector.vector -> string
end
