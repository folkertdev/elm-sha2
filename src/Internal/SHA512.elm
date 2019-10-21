module Internal.SHA512 exposing (DeltaState(..), Digest(..), State(..), Tuple8(..), blockSize, blockToString, calculateDigestDeltas, fromByteValues, fromBytes, fromString, hashBytes, iterate, ks, loopHelp, map16, numberOfWords, padBuffer, reduceBytesMessage, reduceMessage, reduceWordsHelp, toString, u64)

import Array exposing (Array)
import Base64
import Bitwise exposing (and, complement, or, shiftLeftBy, shiftRightZfBy)
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Decode as Decode exposing (Decoder, Step(..))
import Bytes.Encode as Encode
import Hex
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


type Digest
    = Digest Tuple8


type State
    = State Tuple8


type DeltaState
    = DeltaState Tuple8



-- CALCULATING


fromString : State -> String -> Digest
fromString state =
    hashBytes state << Encode.encode << Encode.string


fromByteValues : State -> List Int -> Digest
fromByteValues state input =
    let
        -- try to use unsignedInt32 to represent 4 bytes
        -- much more efficient for large inputs
        pack b1 b2 b3 b4 =
            Encode.unsignedInt32 BE
                (Bitwise.or
                    (Bitwise.or (Bitwise.shiftLeftBy 24 b1) (Bitwise.shiftLeftBy 16 b2))
                    (Bitwise.or (Bitwise.shiftLeftBy 8 b3) b4)
                )

        go accum remaining =
            case remaining of
                b1 :: b2 :: b3 :: b4 :: rest ->
                    go (pack b1 b2 b3 b4 :: accum) rest

                b1 :: rest ->
                    go (Encode.unsignedInt8 b1 :: accum) rest

                [] ->
                    List.reverse accum
    in
    input
        |> go []
        |> Encode.sequence
        |> Encode.encode
        |> hashBytes state


fromBytes : State -> Bytes -> Digest
fromBytes =
    hashBytes


padBuffer : Bytes -> Bytes
padBuffer bytes =
    let
        byteCount =
            Bytes.width bytes

        finalBlockSize =
            -- modBy 128 byteCount, but faster
            Bitwise.and byteCount 0x7F

        paddingSize =
            -- I'm not totally sure where these numbers come from
            -- the 4 is because we encode the length as u32, where u64 is expected
            if finalBlockSize < 112 then
                (111 - finalBlockSize) + 4 + 8

            else
                (239 - finalBlockSize) + 4 + 8

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


hashBytes : State -> Bytes -> Digest
hashBytes state bytes =
    let
        message =
            padBuffer bytes

        numberOfChunks =
            Bytes.width message // 128

        hashState : Decoder State
        hashState =
            iterate numberOfChunks reduceBytesMessage state
    in
    case Decode.decode hashState message of
        Just (State r) ->
            Digest r

        Nothing ->
            case state of
                State r ->
                    Digest r


u64 : Decoder Int64
u64 =
    Int64.decode


reduceBytesMessage : State -> Decoder State
reduceBytesMessage state =
    map16 (reduceMessage state) u64 u64 u64 u64 u64 u64 u64 u64 u64 u64 u64 u64 u64 u64 u64 u64


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
    -- 80 rounds, 80 - 16 = 64
    if i < 64 then
        let
            smallSigma0 =
                let
                    (Int64 x1 x2) =
                        Int64.rotateRightBy 1 b15

                    (Int64 x3 x4) =
                        Int64.rotateRightBy 8 b15

                    (Int64 x5 x6) =
                        Int64.shiftRightZfBy 7 b15
                in
                Int64
                    (x1 |> Bitwise.xor x3 |> Bitwise.xor x5)
                    (x2 |> Bitwise.xor x4 |> Bitwise.xor x6)

            smallSigma1 =
                let
                    (Int64 x1 x2) =
                        Int64.rotateRightBy 19 b2

                    (Int64 x3 x4) =
                        Int64.rotateRightBy 61 b2

                    (Int64 x5 x6) =
                        Int64.shiftRightZfBy 6 b2
                in
                Int64
                    (x1 |> Bitwise.xor x3 |> Bitwise.xor x5)
                    (x2 |> Bitwise.xor x4 |> Bitwise.xor x6)

            w : Int64
            w =
                smallSigma1 |> Int64.add b7 |> Int64.add smallSigma0 |> Int64.add b16
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

        maj =
            Int64.and a (Int64.xor b c)
                |> Int64.xor (Int64.and b c)

        k =
            case Array.get index ks of
                Nothing ->
                    Int64 0 0

                Just v ->
                    v

        bigSigma1 =
            let
                (Int64 x1 x2) =
                    Int64.rotateRightBy 14 e

                (Int64 x3 x4) =
                    Int64.rotateRightBy 18 e

                (Int64 x5 x6) =
                    Int64.rotateRightBy 41 e
            in
            Int64
                (x1 |> Bitwise.xor x3 |> Bitwise.xor x5)
                (x2 |> Bitwise.xor x4 |> Bitwise.xor x6)

        t1 =
            h
                |> Int64.add bigSigma1
                |> Int64.add ch
                |> Int64.add k
                |> Int64.add w

        bigSigma0 =
            let
                (Int64 x1 x2) =
                    Int64.rotateRightBy 28 a

                (Int64 x3 x4) =
                    Int64.rotateRightBy 34 a

                (Int64 x5 x6) =
                    Int64.rotateRightBy 39 a
            in
            Int64
                (x1 |> Bitwise.xor x3 |> Bitwise.xor x5)
                (x2 |> Bitwise.xor x4 |> Bitwise.xor x6)

        t2 =
            bigSigma0
                |> Int64.add maj

        result =
            Tuple8 (Int64.add t1 t2) a b c (Int64.add d t1) e f g
    in
    DeltaState result



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
    Decode.loop ( n, initial ) (loopHelp step)


loopHelp step ( n, state ) =
    if n > 0 then
        step state
            |> Decode.map (\new -> Loop ( n - 1, new ))

    else
        Decode.succeed (Decode.Done state)


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
