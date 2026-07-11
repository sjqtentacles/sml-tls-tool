structure ByteVec :> BYTE_VEC =
struct
  fun toVec s =
    Word8Vector.tabulate (String.size s, fn i =>
      Word8.fromInt (Char.ord (String.sub (s, i))))

  fun fromVec v =
    CharVector.tabulate (Word8Vector.length v, fn i =>
      Char.chr (Word8.toInt (Word8Vector.sub (v, i))))
end
