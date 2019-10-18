module SHA512 exposing
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



-- CONSTANTS


blockSize : Int
blockSize =
    64


numberOfWords : Int
numberOfWords =
    16



-- TYPES


type Tuple8
    = Tuple8 Int64 Int64 Int64 Int64 Int64 Int64 Int64 Int64


toString : Tuple8 -> String
toString (Tuple8 a b c d e f g h) =
    String.join " " (List.map Int64.toHex [ a, b, c, d, e, f, g, h ])


blockToString b16 b15 b14 b13 b12 b11 b10 b9 b8 b7 b6 b5 b4 b3 b2 b1 =
    [ b16, b15, b14, b13, b12, b11, b10, b9, b8, b7, b6, b5, b4, b3, b2, b1 ]
        |> List.reverse
        |> List.map Int64.toHex
        |> String.join " "


{-| A type to represent a message digest. `SHA1.Digest`s are equatable, and you may
want to consider keeping any digests you need in your `Model` as `Digest`s, not
as `String`s created by [`toHex`](#toHex) or [`toBase64`](#toBase64).
-}
type Digest
    = Digest Tuple8


type State
    = State Tuple8


type DeltaState
    = DeltaState Tuple8



-- CALCULATING


{-| Create a digest from a `String`.

    "hello world" |> SHA1.fromString |> SHA1.toHex
    --> "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"

-}
fromString : String -> Digest
fromString =
    hashBytesValue << Encode.encode << Encode.string


{-| Sometimes you have binary data that's not representable in a string. Create
a digest from the raw "bytes", i.e. a `List` of `Int`s. Any items not between 0
and 255 are discarded.

    SHA1.fromByteValues [72, 105, 33, 32, 240, 159, 152, 132]
    --> SHA1.fromString "Hi! 😄"

    [0x00, 0xFF, 0x34, 0xA5] |> SHA1.fromByteValues |> SHA1.toBase64
    --> "sVQuFckyE6K3fsdLmLHmq8+J738="

-}
fromByteValues : List Int -> Digest
fromByteValues input =
    input
        |> List.map Encode.unsignedInt8
        |> Encode.sequence
        |> Encode.encode
        |> hashBytesValue


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
    hashBytesValue


padBuffer : Bytes -> Bytes
padBuffer bytes =
    let
        byteCount =
            Bytes.width bytes

        mdi =
            -- modBy 128 byteCount, but faster
            Bitwise.and byteCount 0x7F

        paddingSize =
            if mdi < 112 then
                (111 - mdi) + 4 + 8

            else
                (239 - mdi) + 4 + 8

        message =
            Encode.encode
                (Encode.sequence
                    [ Encode.bytes bytes
                    , Encode.unsignedInt8 0x80
                    , Encode.sequence (List.repeat paddingSize (Encode.unsignedInt8 0))
                    , Encode.unsignedInt32 BE (Bitwise.shiftLeftBy 3 byteCount)
                    ]
                )
    in
    message


hashBytesValue : Bytes -> Digest
hashBytesValue bytes =
    let
        byteCount =
            Bytes.width bytes

        -- The full message (message + 1 byte for message end flag (0x80) + 8 bytes for message length)
        -- has to be a multiple of 64 bytes (i.e. of 512 bits).
        -- The 4 is because the bitCountInBytes is supposed to be 8 long, but it's only 4 (8 - 4 = 4)
        zeroBytesToAppend =
            4 + modBy 128 (120 - modBy 128 (byteCount + 1))

        numberOfChunks =
            Bytes.width message // 128

        message =
            padBuffer bytes

        -- The `Decode.succeed ()` is required! it fixes a weird issue with large buffers
        -- allocating many large buffers can make SHA1 non-deterministic somehow
        -- (I'm not sure why that is right now, and if it's an elm problem or something deeper)
        -- in any case, the `Decode.andThen` fixes the issue
        hashState : Decoder State
        hashState =
            Decode.succeed ()
                |> Decode.andThen (\_ -> iterate numberOfChunks reduceBytesMessage initialState)
    in
    case Decode.decode hashState message of
        Just (State digest) ->
            Digest digest

        Nothing ->
            -- impossible case
            case initialState of
                State digest ->
                    -- Digest digest
                    Debug.todo "impossible"


i64 : Decoder Int64
i64 =
    Int64.decode


reduceBytesMessage : State -> Decoder State
reduceBytesMessage state =
    map16 (reduceMessage state) i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64


reduceMessage (State ((Tuple8 h0 h1 h2 h3 h4 h5 h6 h7) as initial)) b16 b15 b14 b13 b12 b11 b10 b9 b8 b7 b6 b5 b4 b3 b2 b1 =
    let
        initialDeltaState =
            DeltaState initial
                |> calculateDigestDeltas 0 b1
                |> calculateDigestDeltas 1 b2
                |> calculateDigestDeltas 2 b3
                |> calculateDigestDeltas 3 b4
                |> calculateDigestDeltas 4 b5
                |> calculateDigestDeltas 5 b6
                |> calculateDigestDeltas 6 b7
                |> calculateDigestDeltas 7 b8
                |> calculateDigestDeltas 8 b9
                |> calculateDigestDeltas 9 b10
                |> calculateDigestDeltas 10 b11
                |> calculateDigestDeltas 11 b12
                |> calculateDigestDeltas 12 b13
                |> calculateDigestDeltas 13 b14
                |> calculateDigestDeltas 14 b15
                |> calculateDigestDeltas 15 b16

        (DeltaState (Tuple8 a b c d e f g h)) =
            reduceWordsHelp 0 initialDeltaState b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 b15 b16
    in
    State
        (Tuple8
            (Int64.add h0 a)
            (Int64.add h1 b)
            (Int64.add h2 c)
            (Int64.add h3 d)
            (Int64.add h4 e)
            (Int64.add h5 f)
            (Int64.add h6 g)
            (Int64.add h7 h)
        )


{-| Fold over the words, calculate the delta and combine with the delta state.

We must keep track of the 16 most recent values, and use plain arguments for efficiency reasons.
So in the recursion, `b16` is dropped, all the others shift one position to the left, and `value` is the final argument.
Then the `deltaState` is also updated with the `value`.

-}
reduceWordsHelp i deltaState b16 b15 b14 b13 b12 b11 b10 b9 b8 b7 b6 b5 b4 b3 b2 b1 =
    if i < (80 - 16) then
        let
            w : Int64
            w =
                smallSigma1 b2 |> Int64.add b7 |> Int64.add (smallSigma0 b15) |> Int64.add b16 |> Int64.toUnsigned
        in
        reduceWordsHelp (i + 1) (calculateDigestDeltas (i + numberOfWords) w deltaState) b15 b14 b13 b12 b11 b10 b9 b8 b7 b6 b5 b4 b3 b2 b1 w

    else
        deltaState


calculateDigestDeltas : Int -> Int64 -> DeltaState -> DeltaState
calculateDigestDeltas index w (DeltaState (Tuple8 a b c d e f g h)) =
    let
        ch =
            Int64.and e f
                |> Int64.xor (Int64.and (Int64.complement e) g)
                |> Int64.toUnsigned

        maj x y z =
            Int64.and x y
                |> Int64.xor (Int64.and x z)
                |> Int64.xor (Int64.and y z)
                |> Int64.toUnsigned

        k =
            case Array.get index ks of
                Nothing ->
                    Debug.todo "wrong"

                Just v ->
                    v

        t1 =
            h
                |> Int64.add (bigSigma1 e)
                |> Int64.add ch
                |> Int64.add k
                |> Int64.add w

        t2 =
            bigSigma0 a
                |> Int64.add (maj a b c)

        result =
            Tuple8 (Int64.add t1 t2) a b c (Int64.add d t1) e f g
    in
    DeltaState result


trim =
    Int64.shiftRightZfBy 0


bigSigma0 x =
    Int64.rotateRightBy 28 x
        |> Int64.xor (Int64.rotateRightBy 34 x)
        |> Int64.xor (Int64.rotateRightBy 39 x)
        |> Int64.toUnsigned


bigSigma1 x =
    Int64.rotateRightBy 14 x
        |> Int64.xor (Int64.rotateRightBy 18 x)
        |> Int64.xor (Int64.rotateRightBy 41 x)
        |> Int64.toUnsigned


smallSigma0 x =
    Int64.rotateRightBy 1 x
        |> Int64.xor (Int64.rotateRightBy 8 x)
        |> Int64.xor (Int64.shiftRightZfBy 7 x)
        |> Int64.toUnsigned


smallSigma1 x =
    Int64.rotateRightBy 19 x
        |> Int64.xor (Int64.rotateRightBy 61 x)
        |> Int64.xor (Int64.shiftRightZfBy 6 x)
        |> Int64.toUnsigned


initialState : State
initialState =
    State
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



-- HELPERS


{-| The most efficient implmenentation for `map16`, given that `Decode.map5` is the highest defined in Kernel code
-}
map16 :
    (b1 -> b2 -> b3 -> b4 -> b5 -> b6 -> b7 -> b8 -> b9 -> b10 -> b11 -> b12 -> b13 -> b14 -> b15 -> b16 -> result)
    -> Decoder b1
    -> Decoder b2
    -> Decoder b3
    -> Decoder b4
    -> Decoder b5
    -> Decoder b6
    -> Decoder b7
    -> Decoder b8
    -> Decoder b9
    -> Decoder b10
    -> Decoder b11
    -> Decoder b12
    -> Decoder b13
    -> Decoder b14
    -> Decoder b15
    -> Decoder b16
    -> Decoder result
map16 f b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 b15 b16 =
    Decode.succeed f
        |> Decode.map5 (\a b c d e -> e d c b a) b4 b3 b2 b1
        |> Decode.map5 (\a b c d e -> e d c b a) b8 b7 b6 b5
        |> Decode.map5 (\a b c d e -> e d c b a) b12 b11 b10 b9
        |> Decode.map5 (\a b c d e -> e d c b a) b16 b15 b14 b13


{-| Iterate a decoder `n` times

Needs some care to not run into stack overflow. This definition is nicely tail-recursive.

-}
iterate : Int -> (a -> Decoder a) -> a -> Decoder a
iterate n step initial =
    iterateHelp n (\value -> Decode.andThen step value) (Decode.succeed initial)


iterateHelp n step initial =
    if n > 0 then
        iterateHelp (n - 1) step (step initial)

    else
        initial


ks =
    Array.fromList
        [ Int64 0x428A2F98 0xD728AE22
        , Int64 0x71374491 0x23EF65CD
        , Int64 0xB5C0FBCF 0xEC4D3B2F
        , Int64 0xE9B5DBA5 0x8189DBBC
        , Int64 0x3956C25B 0xF348B538
        , Int64 0x59F111F1 0xB605D019
        , Int64 0x923F82A4 0xAF194F9B
        , Int64 0xAB1C5ED5 0xDA6D8118
        , Int64 0xD807AA98 0xA3030242
        , Int64 0x12835B01 0x45706FBE
        , Int64 0x243185BE 0x4EE4B28C
        , Int64 0x550C7DC3 0xD5FFB4E2
        , Int64 0x72BE5D74 0xF27B896F
        , Int64 0x80DEB1FE 0x3B1696B1
        , Int64 0x9BDC06A7 0x25C71235
        , Int64 0xC19BF174 0xCF692694
        , Int64 0xE49B69C1 0x9EF14AD2
        , Int64 0xEFBE4786 0x384F25E3
        , Int64 0x0FC19DC6 0x8B8CD5B5
        , Int64 0x240CA1CC 0x77AC9C65
        , Int64 0x2DE92C6F 0x592B0275
        , Int64 0x4A7484AA 0x6EA6E483
        , Int64 0x5CB0A9DC 0xBD41FBD4
        , Int64 0x76F988DA 0x831153B5
        , Int64 0x983E5152 0xEE66DFAB
        , Int64 0xA831C66D 0x2DB43210
        , Int64 0xB00327C8 0x98FB213F
        , Int64 0xBF597FC7 0xBEEF0EE4
        , Int64 0xC6E00BF3 0x3DA88FC2
        , Int64 0xD5A79147 0x930AA725
        , Int64 0x06CA6351 0xE003826F
        , Int64 0x14292967 0x0A0E6E70
        , Int64 0x27B70A85 0x46D22FFC
        , Int64 0x2E1B2138 0x5C26C926
        , Int64 0x4D2C6DFC 0x5AC42AED
        , Int64 0x53380D13 0x9D95B3DF
        , Int64 0x650A7354 0x8BAF63DE
        , Int64 0x766A0ABB 0x3C77B2A8
        , Int64 0x81C2C92E 0x47EDAEE6
        , Int64 0x92722C85 0x1482353B
        , Int64 0xA2BFE8A1 0x4CF10364
        , Int64 0xA81A664B 0xBC423001
        , Int64 0xC24B8B70 0xD0F89791
        , Int64 0xC76C51A3 0x0654BE30
        , Int64 0xD192E819 0xD6EF5218
        , Int64 0xD6990624 0x5565A910
        , Int64 0xF40E3585 0x5771202A
        , Int64 0x106AA070 0x32BBD1B8
        , Int64 0x19A4C116 0xB8D2D0C8
        , Int64 0x1E376C08 0x5141AB53
        , Int64 0x2748774C 0xDF8EEB99
        , Int64 0x34B0BCB5 0xE19B48A8
        , Int64 0x391C0CB3 0xC5C95A63
        , Int64 0x4ED8AA4A 0xE3418ACB
        , Int64 0x5B9CCA4F 0x7763E373
        , Int64 0x682E6FF3 0xD6B2B8A3
        , Int64 0x748F82EE 0x5DEFB2FC
        , Int64 0x78A5636F 0x43172F60
        , Int64 0x84C87814 0xA1F0AB72
        , Int64 0x8CC70208 0x1A6439EC
        , Int64 0x90BEFFFA 0x23631E28
        , Int64 0xA4506CEB 0xDE82BDE9
        , Int64 0xBEF9A3F7 0xB2C67915
        , Int64 0xC67178F2 0xE372532B
        , Int64 0xCA273ECE 0xEA26619C
        , Int64 0xD186B8C7 0x21C0C207
        , Int64 0xEADA7DD6 0xCDE0EB1E
        , Int64 0xF57D4F7F 0xEE6ED178
        , Int64 0x06F067AA 0x72176FBA
        , Int64 0x0A637DC5 0xA2C898A6
        , Int64 0x113F9804 0xBEF90DAE
        , Int64 0x1B710B35 0x131C471B
        , Int64 0x28DB77F5 0x23047D84
        , Int64 0x32CAAB7B 0x40C72493
        , Int64 0x3C9EBE0A 0x15C9BEBC
        , Int64 0x431D67C4 0x9C100D4C
        , Int64 0x4CC5D4BE 0xCB3E42B6
        , Int64 0x597F299C 0xFC657E2A
        , Int64 0x5FCB6FAB 0x3AD6FAEC
        , Int64 0x6C44198C 0x4A475817
        ]



-- 61626364 65666768 62636465 66676869 63646566 6768696A 64656667 68696A6B 65666768 696A6B6C 66676869 6A6B6C6D 6768696A 6B6C6D6E 68696A6B 6C6D6E6F 696A6B6C 6D6E6F70 6A6B6C6D 6E6F7071 6B6C6D6E 6F707172 6C6D6E6F 70717273 6D6E6F70 71727374 6E6F7071 72737475 80000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000380"]
-- 61626364 65666768 62636465 66676869 63646566 6768696a 64656667 68696a6b 65666768 696a6b6c 66676869 6a6b6c6d 6768696a 6b6c6d6e 68696a6b 6c6d6e6f 696a6b6c 6d6e6f70 6a6b6c6d 6e6f7071 6b6c6d6e 6f707172 6c6d6e6f 70717273 6d6e6f70 71727374 6e6f7071 72737475 80000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000380
