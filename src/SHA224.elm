module SHA224 exposing
    ( Digest
    , fromString
    , toHex, toBase64
    , fromBytes, toBytes
    , fromByteValues, toByteValues
    )

{-| [SHA-1] is a [cryptographic hash function].
Although it is no longer considered cryptographically secure (as collisions can
be found faster than brute force), it is still very suitable for a broad range
of uses, and is a lot stronger than MD5.

[SHA-1]: https://en.wikipedia.org/wiki/SHA-1
[cryptographic hash function]: https://en.wikipedia.org/wiki/Cryptographic_hash_function

This package provides a way of creating SHA-1 digests from `String`s and `List
Int`s (where each `Int` is between 0 and 255, and represents a byte). It can
also take those `Digest`s and format them in [hexadecimal] or [base64] notation.
Alternatively, you can get the binary digest, using a `List  Int` to represent
the bytes.

[hexadecimal]: https://en.wikipedia.org/wiki/Hexadecimal
[base64]: https://en.wikipedia.org/wiki/Base64

**Note:** Currently, the package can only create digests for around 200kb of
data. If there is any interest in using this package for hashing >200kb, or for
hashing [elm/bytes], [let me know][issues]!

[elm/bytes]: https://github.com/elm/bytes
[issues]: https://github.com/TSFoster/elm-sha1/issues

@docs Digest


# Creating digests

@docs fromString


# Formatting digests

@docs toHex, toBase64


# Binary data

@docs fromBytes, toBytes
@docs fromByteValues, toByteValues

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


{-| A type to represent a message digest. `SHA1.Digest`s are equatable, and you may
want to consider keeping any digests you need in your `Model` as `Digest`s, not
as `String`s created by [`toHex`](#toHex) or [`toBase64`](#toBase64).
-}
type Digest
    = Digest Tuple7


convertDigest : Internal.Digest -> Digest
convertDigest (Internal.Digest (Tuple8 a b c d e f g _)) =
    Digest (Tuple7 a b c d e f g)



-- CALCULATING


{-| Create a digest from a `String`.

    "hello world" |> SHA1.fromString |> SHA1.toHex
    --> "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"

-}
fromString : String -> Digest
fromString =
    convertDigest << Internal.fromString initialState


{-| Sometimes you have binary data that's not representable in a string. Create
a digest from the raw "bytes", i.e. a `List` of `Int`s. Any items not between 0
and 255 are discarded.

    SHA1.fromByteValues [72, 105, 33, 32, 240, 159, 152, 132]
    --> SHA1.fromString "Hi! 😄"

    [0x00, 0xFF, 0x34, 0xA5] |> SHA1.fromByteValues |> SHA1.toBase64
    --> "sVQuFckyE6K3fsdLmLHmq8+J738="

-}
fromByteValues : List Int -> Digest
fromByteValues =
    convertDigest << Internal.fromByteValues initialState


{-| Create a digest from a [`Bytes`](https://package.elm-lang.org/packages/elm/bytes/latest/)

    import Bytes.Encode as Encode
    import Bytes exposing (Bytes, Endianness(..))

    buffer : Bytes
    buffer = Encode.encode (Encode.unsignedInt32 BE 42)

    SHA1.fromBytes buffer
        |> SHA1.toHex
        --> "25f0c736f1fad0770bbb9a265ded159517c1e68c"

-}
fromBytes : Bytes -> Digest
fromBytes =
    convertDigest << Internal.hashBytes initialState


initialState : Internal.State
initialState =
    Internal.State
        (Tuple8 0xC1059ED8 0x367CD507 0x3070DD17 0xF70E5939 0xFFC00B31 0x68581511 0x64F98FA7 0xBEFA4FA4)



-- FORMATTING


{-| If you need the raw digest instead of the textual representation (for
example, if using SHA-1 as part of another algorithm), `toBytes` is what you're
looking for!

    "And the band begins to play"
        |> SHA1.fromString
        |> SHA1.toByteValues
    --> [ 0xF3, 0x08, 0x73, 0x13
    --> , 0xD6, 0xBC, 0xE5, 0x5B
    --> , 0x60, 0x0C, 0x69, 0x2F
    --> , 0xE0, 0x92, 0xF4, 0x53
    --> , 0x87, 0x3F, 0xAE, 0x91
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


{-| Turn a digest into `Bytes`.

The digest is stored as 5 big-endian 32-bit unsigned integers, so the width is 20 bytes or 160 bits.

-}
toBytes : Digest -> Bytes
toBytes =
    Encode.encode << toEncoder


{-| One of the two canonical ways of representing a SHA-1 digest is with 40
hexadecimal digits.

    "And our friends are all aboard"
        |> SHA1.fromString
        |> SHA1.toHex
    --> "f9a0c23ddcd40f6956b0cf59cd9b8800d71de73d"

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


{-| One of the two canonical ways of representing a SHA-1 digest is in a 20
digit long Base64 binary to ASCII text encoding.

    "Many more of them live next door"
        |> SHA1.fromString
        |> SHA1.toBase64
    --> "jfL0oVb5xakab6BMLplGe2XPbj8="

-}
toBase64 : Digest -> String
toBase64 digest =
    digest
        |> toEncoder
        |> Encode.encode
        |> Base64.fromBytes
        |> Maybe.withDefault ""
