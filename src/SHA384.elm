module SHA384 exposing
    ( Digest
    , fromString
    , fromBytes
    , fromByteValues
    , toHex, toBase64
    , toBytes, toByteValues
    )

{-| [SHA-384] is a [cryptographic hash function] that gives 192 bits of security.

[SHA-384]: http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
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
import Hex.Convert
import Int64 exposing (Int64(..))
import Internal.SHA512 as Internal exposing (Digest(..), Tuple8(..))



-- TYPES


type Tuple6
    = Tuple6 Int64 Int64 Int64 Int64 Int64 Int64


{-| Abstract representation of a sha384 digest.
-}
type Digest
    = Digest Tuple6


convertDigest : Internal.Digest -> Digest
convertDigest (Internal.Digest (Tuple8 a b c d e f _ _)) =
    Digest (Tuple6 a b c d e f)



-- CALCULATING


{-| Create a digest from a `String`.

    "hello world"
        |> SHA384.fromString
        |> SHA384.toHex
    --> "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd"

-}
fromString : String -> Digest
fromString =
    convertDigest << Internal.fromString initialState


{-| Create a digest from integer byte values. Values are considered mod 256, which means that larger than 255 overflow.

    SHA384.fromByteValues
        [72, 105, 33, 32, 240, 159, 152, 132]
    --> SHA384.fromString "Hi! 😄"

    [0x00, 0xFF, 0x34, 0xA5]
        |> SHA384.fromByteValues
        |> SHA384.toBase64
    --> "6uus8pWKLDBg2APcRPhqSZrfwu+Y71cgQjcEKu+k80yR4H8s6NimoiR00HKMGSW9"

-}
fromByteValues : List Int -> Digest
fromByteValues =
    convertDigest << Internal.fromByteValues initialState


{-| Create a digest from a [`Bytes`](https://package.elm-lang.org/packages/elm/bytes/latest/)

    import Bytes.Encode as Encode
    import Bytes exposing (Bytes, Endianness(..))

    buffer : Bytes
    buffer = Encode.encode (Encode.unsignedInt32 BE 42)

    SHA384.fromBytes buffer
        |> SHA384.toHex
        --> "169c6e0f2a73b8a3f0c6dad952ab62ee64136652d1bfcf5901951186384324070819bba50666c9371265b68b7a57410d"

-}
fromBytes : Bytes -> Digest
fromBytes =
    convertDigest << Internal.hashBytes initialState


initialState : Internal.State
initialState =
    Internal.State
        (Tuple8
            (Int64 0xCBBB9D5D 0xC1059ED8)
            (Int64 0x629A292A 0x367CD507)
            (Int64 0x9159015A 0x3070DD17)
            (Int64 0x152FECD8 0xF70E5939)
            (Int64 0x67332667 0xFFC00B31)
            (Int64 0x8EB44A87 0x68581511)
            (Int64 0xDB0C2E0D 0x64F98FA7)
            (Int64 0x47B5481D 0xBEFA4FA4)
        )



-- FORMATTING


{-| Get the individual byte values as integers.

    "And the band begins to play"
        |> SHA384.fromString
        |> SHA384.toByteValues
    --> [216,234,215,67,129,199,177,6,4,113,130,141,149,211,213,72,182,77,43,191,48,162,210,207,88,239,69,109,211,248,187,238,97,27,125,162,116,132,44,35,116,33,51,81,115,241,201,137]

-}
toByteValues : Digest -> List Int
toByteValues (Digest (Tuple6 a b c d e f)) =
    List.concatMap Int64.toByteValues [ a, b, c, d, e, f ]


toEncoder : Digest -> Encode.Encoder
toEncoder (Digest (Tuple6 a b c d e f)) =
    Encode.sequence
        [ Int64.toEncoder a
        , Int64.toEncoder b
        , Int64.toEncoder c
        , Int64.toEncoder d
        , Int64.toEncoder e
        , Int64.toEncoder f
        ]


{-| Turn a digest into `Bytes`.

The digest is stored as 7 big-endian 64-bit unsigned integers, so the width is 48 bytes or 384 bits.

-}
toBytes : Digest -> Bytes
toBytes =
    Encode.encode << toEncoder


{-| Represent the digest as a hexadecimal string.

    "And our friends are all aboard"
        |> SHA384.fromString
        |> SHA384.toHex
    --> "8b955c0b596df8b93db7c9a0105098c5be18bd4dbbea4cccf9b4b138c54668d0c9295485dc3b20a1ecd1bf97762f3b47"

-}
toHex : Digest -> String
toHex (Digest (Tuple6 a b c d e f)) =
    Int64.toHex a
        ++ Int64.toHex b
        ++ Int64.toHex c
        ++ Int64.toHex d
        ++ Int64.toHex e
        ++ Int64.toHex f



-- Base64 uses 1 character per 6 bits, which doesn't divide very nicely into our
-- 5 32-bit  integers! The  base64 digest  is 28  characters long,  although the
-- final character  is a '=',  which means it's  padded. Therefore, it  uses 162
-- bits  of entropy  to display  our 160  bit  digest, so  the digest  has 2  0s
-- appended.


{-| Represent a digest as its base-64 encoding.

    "Many more of them live next door"
        |> SHA384.fromString
        |> SHA384.toBase64
    --> "pKq5Z/Msjg14oJ2TGHS21h+L9lMWkASENRmCgur5mpwRNoE3dAPWV6kw+aNX1gmB"

-}
toBase64 : Digest -> String
toBase64 digest =
    digest
        |> toEncoder
        |> Encode.encode
        |> Base64.fromBytes
        |> Maybe.withDefault ""
