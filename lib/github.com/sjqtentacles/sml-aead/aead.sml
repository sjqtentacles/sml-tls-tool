(* aead.sml

   A thin, algorithm-agnostic AEAD facade. This repo deliberately implements NO
   new cryptography: it dispatches to the vendored primitives
     - ChaCha20Poly1305 (sml-chacha20, RFC 8439)
     - AesGcm           (sml-aes, NIST GCM)
   and re-exports the standalone Poly1305 one-time MAC. Its value is one unified
   interface plus the consolidated RFC/NIST vector vault in test/. *)

structure Aead :> AEAD =
struct
  datatype alg = ChaCha20Poly1305
               | AesGcm128
               | AesGcm256

  exception Aead of string

  val tagLen = 16

  fun keyLen ChaCha20Poly1305 = 32
    | keyLen AesGcm128         = 16
    | keyLen AesGcm256         = 32

  (* All three constructions take a 96-bit (12-byte) nonce / IV. *)
  fun nonceLen _ = 12

  fun checkLens alg {key, nonce} =
    let
      val kl = keyLen alg
      val nl = nonceLen alg
    in
      if String.size key <> kl then
        raise Aead ("key must be " ^ Int.toString kl ^ " bytes, got "
                    ^ Int.toString (String.size key))
      else if String.size nonce <> nl then
        raise Aead ("nonce must be " ^ Int.toString nl ^ " bytes, got "
                    ^ Int.toString (String.size nonce))
      else ()
    end

  (* The underlying primitives share the curried shape
       seal  key nonce aad plaintext -> ciphertext||tag
       open' key nonce aad sealed     -> plaintext option *)
  fun primSeal ChaCha20Poly1305 = ChaCha20Poly1305.seal
    | primSeal AesGcm128         = AesGcm.seal
    | primSeal AesGcm256         = AesGcm.seal

  fun primOpen ChaCha20Poly1305 = ChaCha20Poly1305.open'
    | primOpen AesGcm128         = AesGcm.open'
    | primOpen AesGcm256         = AesGcm.open'

  fun seal alg {key, nonce, aad, plaintext} =
    ( checkLens alg {key = key, nonce = nonce}
    ; primSeal alg key nonce aad plaintext )

  fun open' alg {key, nonce, aad, ciphertext} =
    ( checkLens alg {key = key, nonce = nonce}
    ; primOpen alg key nonce aad ciphertext )

  structure Poly1305 =
  struct
    val mac    = Poly1305.mac
    val macHex = Poly1305.macHex
  end
end
