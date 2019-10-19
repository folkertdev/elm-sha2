module SHA512 exposing
    ( Digest
    , fromString
    , fromBytes
    , fromByteValues
    , toHex, toBase64
    , toBytes, toByteValues
    )

{-| [SHA-512] is a [cryptographic hash function] that gives 256 bits of security.

[SHA-512]: http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
[cryptographic hash function]: https://en.wikipedia.org/wiki/Cryptographic_hash_function

@docs Digest


# Creating digests

@docs fromString
@docs fromBytes
@docs fromByteValues


# Formatting digests

@docs toHex, toBase64


# To binary data

@docs toBytes, toByteValues

-}

import Array exposing (Array)
import Base64
import Bitwise exposing (and, complement, or, shiftLeftBy, shiftRightZfBy)
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Decode as Decode exposing (Decoder, Step(..))
import Bytes.Encode as Encode
import Hex
import Int64 exposing (Int64(..))
import Internal.SHA512 as Internal exposing (Digest(..), Tuple8(..))



-- TYPES


{-| Abstract representation of a sha512 digest.
-}
type alias Digest =
    Internal.Digest



-- CALCULATING


{-| Create a digest from a `String`.

    "hello world"
        |> SHA512.fromString
        |> SHA512.toHex
    --> "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"

-}
fromString : String -> Digest
fromString =
    Internal.fromString initialState


{-| Create a digest from integer byte values.
Values are considered mod 256, which means that larger than 255 overflow.

    SHA512.fromByteValues
        [72, 105, 33, 32, 240, 159, 152, 132]
    --> SHA512.fromString "Hi! 😄"

    [0x00, 0xFF, 0x34, 0xA5]
        |> SHA512.fromByteValues
        |> SHA512.toBase64
    --> "El+WnnuwQuhuInw0BkdTlTj/MkFOE/Rx65xiLJxvw5PjAGZ9oow71/el2OGLAULzaFmREAfEy1MWSxNSfsnVgw=="

-}
fromByteValues : List Int -> Digest
fromByteValues =
    Internal.fromByteValues initialState


{-| Create a digest from a [`Bytes`](https://package.elm-lang.org/packages/elm/bytes/latest/)

    import Bytes.Encode as Encode
    import Bytes exposing (Bytes, Endianness(..))

    buffer : Bytes
    buffer = Encode.encode (Encode.unsignedInt32 BE 42)

    SHA512.fromBytes buffer
        |> SHA512.toHex
        --> "08cc3f0991969ae44b05e92bcd8f6ece4dd4e9733a9288dcfff47325906c36ecab9a3c63e59411b3df1f6fed6a232c6a20bff3afff91b36689a41037cbe0b6a0"

-}
fromBytes : Bytes -> Digest
fromBytes =
    Internal.hashBytes initialState


initialState : Internal.State
initialState =
    Internal.State
        (Tuple8
            (Int64 0x6A09E667 0xF3BCC908)
            (Int64 0xBB67AE85 0x84CAA73B)
            (Int64 0x3C6EF372 0xFE94F82B)
            (Int64 0xA54FF53A 0x5F1D36F1)
            (Int64 0x510E527F 0xADE682D1)
            (Int64 0x9B05688C 0x2B3E6C1F)
            (Int64 0x1F83D9AB 0xFB41BD6B)
            (Int64 0x5BE0CD19 0x137E2179)
        )



-- FORMATTING


{-| Get the individual byte values as integers.

    "And the band begins to play"
        |> SHA512.fromString
        |> SHA512.toByteValues
    --> [153,140,77,156,68,193,195,117,134,19,24,147,44,86,45,132,106,110,43,98,221,233,100,27,183,45,33,120,139,31,6,103,128,205,65,65,9,252,111,213,5,60,65,56,181,170,166,85,7,48,58,253,54,121,246,230,31,95,205,70,53,219,78,168]

-}
toByteValues : Digest -> List Int
toByteValues (Digest (Tuple8 a b c d e f g h)) =
    List.concatMap Int64.toByteValues [ a, b, c, d, e, f, g, h ]


toEncoder : Digest -> Encode.Encoder
toEncoder (Digest (Tuple8 a b c d e f g h)) =
    Encode.sequence
        [ Int64.toEncoder a
        , Int64.toEncoder b
        , Int64.toEncoder c
        , Int64.toEncoder d
        , Int64.toEncoder e
        , Int64.toEncoder f
        , Int64.toEncoder g
        , Int64.toEncoder h
        ]


{-| Turn a digest into `Bytes`.

The digest is stored as 8 big-endian 64-bit unsigned integers, so the width is 64 bytes or 512 bits.

-}
toBytes : Digest -> Bytes
toBytes =
    Encode.encode << toEncoder


{-| Represent the digest as a string of hexadecimal digits.

    "And our friends are all aboard"
        |> SHA512.fromString
        |> SHA512.toHex
    --> "5af050bf4b4f2fbb2f032f42521e2e46a1aff6dcd02176c31425d8777abbe5c818375de27fd8d83cd848621a85507d1bd19eb35c70152c0f8e77b9ba3104e669"

-}
toHex : Digest -> String
toHex (Digest (Tuple8 a b c d e f g h)) =
    Int64.toHex a
        ++ Int64.toHex b
        ++ Int64.toHex c
        ++ Int64.toHex d
        ++ Int64.toHex e
        ++ Int64.toHex f
        ++ Int64.toHex g
        ++ Int64.toHex h



-- Base64 uses 1 character per 6 bits, which doesn't divide very nicely into our
-- 5 32-bit  integers! The  base64 digest  is 28  characters long,  although the
-- final character  is a '=',  which means it's  padded. Therefore, it  uses 162
-- bits  of entropy  to display  our 160  bit  digest, so  the digest  has 2  0s
-- appended.


{-| Represent the digest as its base-64 encoding.

    "Many more of them live next door"
        |> SHA512.fromString
        |> SHA512.toBase64
    --> "cyr6xhwqW4Fk9Gm5R4h/dqFxkPOf/gPHKiI6t00qQFC8QJAP65IlZkS4YhdGxTvL7VPFzlSPAoXtPTxPAmVJrg=="

-}
toBase64 : Digest -> String
toBase64 digest =
    digest
        |> toEncoder
        |> Encode.encode
        |> Base64.fromBytes
        |> Maybe.withDefault ""
