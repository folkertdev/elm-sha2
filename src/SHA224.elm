module SHA224 exposing
    ( Digest
    , fromString
    , fromBytes
    , fromByteValues
    , toHex, toBase64
    , toBytes, toByteValues
    )

{-| [SHA-224] is a [cryptographic hash function] that gives 112 bits of security.

[SHA-224]: https://tools.ietf.org/rfc/rfc3874.txt
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
import Internal.SHA256 as Internal exposing (Digest(..), Tuple8(..))



-- TYPES


type Tuple7
    = Tuple7 Int Int Int Int Int Int Int


{-| Abstract representation of a sha224 digest.
-}
type Digest
    = Digest Tuple7


{-| drop the final u32 from a sha256 digest
-}
convertDigest : Internal.Digest -> Digest
convertDigest (Internal.Digest (Tuple8 a b c d e f g _)) =
    Digest (Tuple7 a b c d e f g)



-- CALCULATING


{-| Create a digest from a `String`.

    "hello world"
        |> SHA224.fromString
        |> SHA224.toHex
    --> "12f05477fc24bb4faefd865171156dafde1cec45b8ad3cf2522a563582b"

-}
fromString : String -> Digest
fromString =
    convertDigest << Internal.fromString initialState


{-| Create a digest from integer byte values.
Values are considered mod 256, which means that larger than 255 overflow.

    SHA224.fromByteValues
        [72, 105, 33, 32, 240, 159, 152, 132 ]
    --> SHA224.fromString "Hi! 😄"

    [0x00, 0xFF, 0x34, 0xA5]
        |> SHA224.fromByteValues
        |> SHA224.toBase64
    --> "XNMoqDRg7RdO+hXuACw+BWAVTd8aTNqXyjz35w=="

-}
fromByteValues : List Int -> Digest
fromByteValues =
    convertDigest << Internal.fromByteValues initialState


{-| Create a digest from a [`Bytes`](https://package.elm-lang.org/packages/elm/bytes/latest/)

    import Bytes.Encode as Encode
    import Bytes exposing (Bytes, Endianness(..))

    buffer : Bytes
    buffer = Encode.encode (Encode.unsignedInt32 BE 42)

    SHA224.fromBytes buffer
        |> SHA224.toHex
        --> "1793ce43981dc8ea9c80d55181905c629b154dec6c914152e7dbb08a4177"

-}
fromBytes : Bytes -> Digest
fromBytes =
    convertDigest << Internal.hashBytes initialState


initialState : Internal.State
initialState =
    Internal.State
        (Tuple8 0xC1059ED8 0x367CD507 0x3070DD17 0xF70E5939 0xFFC00B31 0x68581511 0x64F98FA7 0xBEFA4FA4)



-- FORMATTING


{-| Get the individual byte values as integers.

    "And the band begins to play"
        |> SHA224.fromString
        |> SHA224.toByteValues
    --> [ 0xac, 0x41, 0xa7, 0x63
    --> , 0x89, 0xc4, 0xe1, 0x5a
    --> , 0x7e, 0x3b, 0x9d, 0x4a
    --> , 0x24, 0x20, 0xef, 0xd0
    --> , 0x32, 0x78, 0xd8, 0xfc
    --> , 0xcb, 0x23, 0x39, 0xa1
    --> , 0xe6, 0xaf, 0xcd, 0x18
    --> ]

-}
toByteValues : Digest -> List Int
toByteValues (Digest (Tuple7 a b c d e f g)) =
    List.concatMap wordToBytes [ a, b, c, d, e, f, g ]


wordToBytes : Int -> List Int
wordToBytes int =
    [ int |> shiftRightZfBy 0x18 |> and 0xFF
    , int |> shiftRightZfBy 0x10 |> and 0xFF
    , int |> shiftRightZfBy 0x08 |> and 0xFF
    , int |> and 0xFF
    ]


toEncoder : Digest -> Encode.Encoder
toEncoder (Digest (Tuple7 a b c d e f g)) =
    Encode.sequence
        [ Encode.unsignedInt32 BE a
        , Encode.unsignedInt32 BE b
        , Encode.unsignedInt32 BE c
        , Encode.unsignedInt32 BE d
        , Encode.unsignedInt32 BE e
        , Encode.unsignedInt32 BE f
        , Encode.unsignedInt32 BE g
        ]


{-| Turn a digest into `Bytes`. The digest is stored as 7 big-endian 32-bit unsigned integers, so the width is 28 bytes or 224 bits.
-}
toBytes : Digest -> Bytes
toBytes =
    Encode.encode << toEncoder


{-| Represent the digest as a string of hexadecimal digits.

    "And our friends are all aboard"
        |> SHA224.fromString
        |> SHA224.toHex
    --> "143baf0c15656c9c0ecce1e4c1cb8491e61e5fe01c510e33d733138e899cb"

-}
toHex : Digest -> String
toHex (Digest (Tuple7 a b c d e f g)) =
    format a
        ++ format b
        ++ format c
        ++ format d
        ++ format e
        ++ format f
        ++ format g


format x =
    Hex.toString x
        |> String.padLeft 8 '0'



-- Base64 uses 1 character per 6 bits, which doesn't divide very nicely into our
-- 5 32-bit  integers! The  base64 digest  is 28  characters long,  although the
-- final character  is a '=',  which means it's  padded. Therefore, it  uses 162
-- bits  of entropy  to display  our 160  bit  digest, so  the digest  has 2  0s
-- appended.


{-| Represent the digest as its base-64 encoding.

    "Many more of them live next door"
        |> SHA224.fromString
        |> SHA224.toBase64
    --> "jGqILHEjFHl4RGN0oaRtFhktytsyncZyOHob4g=="

-}
toBase64 : Digest -> String
toBase64 digest =
    digest
        |> toEncoder
        |> Encode.encode
        |> Base64.fromBytes
        |> Maybe.withDefault ""
