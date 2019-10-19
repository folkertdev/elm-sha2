module TestSha512 exposing (..)

import Bitwise exposing (..)
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Decode as Decode exposing (Decoder, Step(..))
import Bytes.Encode as Encode
import Expect exposing (Expectation)
import Fuzz exposing (Fuzzer, int, list, string)
import Hex.Convert
import Int64 exposing (Int64(..))
import Internal.SHA512 as Internal
import SHA512
import Test exposing (..)


bigSigma1 e =
    Int64.rotateRightBy 14 e
        |> Int64.xor (Int64.rotateRightBy 18 e)
        |> Int64.xor (Int64.rotateRightBy 41 e)


maxInt64 =
    Int64 0xFFFFFFFF 0xFFFFFFFF


y =
    Int64 0x01 0xFFFFFFFF


paddedBlock1 =
    [ "61626380"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000018"
    ]


paddedBlock2 =
    [ "61626364"
    , "65666768"
    , "62636465"
    , "66676869"
    , "63646566"
    , "6768696a"
    , "64656667"
    , "68696a6b"
    , "65666768"
    , "696a6b6c"
    , "66676869"
    , "6a6b6c6d"
    , "6768696a"
    , "6b6c6d6e"
    , "68696a6b"
    , "6c6d6e6f"
    , "696a6b6c"
    , "6d6e6f70"
    , "6a6b6c6d"
    , "6e6f7071"
    , "6b6c6d6e"
    , "6f707172"
    , "6c6d6e6f"
    , "70717273"
    , "6d6e6f70"
    , "71727374"
    , "6e6f7071"
    , "72737475"
    , "80000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000000"
    , "00000380"
    ]


oneMillion =
    test "1 000 000 as" <|
        \_ ->
            String.repeat 1000000 "a"
                |> SHA512.fromString
                |> SHA512.toHex
                |> Expect.equal "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"


spec =
    describe "tests from the spec"
        [ describe "spec example 1"
            [ test "abc" <|
                \_ ->
                    "abc"
                        |> SHA512.fromString
                        |> SHA512.toHex
                        |> Expect.equal "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            , test "pad message" <|
                \_ ->
                    let
                        msg =
                            "abc"
                    in
                    Encode.encode (Encode.string msg)
                        |> Internal.padBuffer
                        |> Hex.Convert.toString
                        |> Hex.Convert.blocks 8
                        |> List.map String.toLower
                        |> Expect.equal paddedBlock1
            ]
        , describe "spec example 2"
            [ test "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" <|
                \_ ->
                    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
                        |> SHA512.fromString
                        |> SHA512.toHex
                        |> Expect.equal "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
            , test "pad message" <|
                \_ ->
                    let
                        msg =
                            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
                    in
                    Encode.encode (Encode.string msg)
                        |> Internal.padBuffer
                        |> Hex.Convert.toString
                        |> Hex.Convert.blocks 8
                        |> List.map String.toLower
                        |> Expect.equal paddedBlock2
            , test "big sigma 2" <|
                \_ ->
                    bigSigma1 (Int64 0xE4D35B61 0x3A5AC420)
                        |> Int64.toHex
                        |> Expect.equal (Int64 0x1116871B 0xAB2ECE50 |> Int64.toHex)
            , test "ch" <|
                \_ ->
                    let
                        e =
                            Int64 0xE4D35B61 0x3A5AC420

                        f =
                            Int64 0xEC9C5E98 0xFF98760D

                        g =
                            Int64 0x49D5FA3A 0x16DCD502

                        ch =
                            Int64.and e f
                                |> Int64.xor (Int64.and (Int64.complement e) g)
                                |> Int64.toUnsigned
                    in
                    ch
                        |> Int64.toHex
                        |> Expect.equal (Int64 0xED94FA1A 0x3E9C5502 |> Int64.toHex)
            , test "t1" <|
                \_ ->
                    let
                        e =
                            Int64 0xE4D35B61 0x3A5AC420

                        ch =
                            Int64 0xED94FA1A 0x3E9C5502

                        h =
                            Int64 0xBE58522C 0xB9590EE1

                        k =
                            Int64 0xC19BF174 0xCF692694

                        w =
                            Int64 0x00 0x00

                        t1 =
                            h
                                |> Int64.add (bigSigma1 e)
                                |> Int64.add ch
                                |> Int64.add k
                                |> Int64.add w
                    in
                    t1
                        |> Int64.toHex
                        |> Expect.equal (Int64 0x7E9FC4D7 0x728D58C7 |> Int64.toHex)
            , test "t1 +  d" <|
                \_ ->
                    let
                        d =
                            Int64 0xF17F52FB 0x02F4EB74

                        t1 =
                            Int64 0x7E9FC4D7 0x728D58C7
                    in
                    Int64.add t1 d
                        |> Int64.toHex
                        |> Expect.equal (Int64 0x701F17D2 0x7582443B |> Int64.toHex)
            ]
        ]


suite : Test
suite =
    describe "Int64"
        [ test "big sigma" <|
            \_ ->
                bigSigma1 (Int64 0x510E527F 0xADE682D1)
                    |> Int64.toHex
                    |> Expect.equal (Int64 0x9427E33B 0xB5C9DBCA |> Int64.toHex)
        , describe "rotateRightBy 14 tests"
            [ test "rotateRightBy 14" <|
                \_ ->
                    Int64 0x510E527F 0xADE682D1
                        |> Int64.rotateRightBy 14
                        |> Int64.toHex
                        |> Expect.equal (Int64 0x0B454439 0x49FEB79A |> Int64.toHex)
            , test "big sigma 1 3 " <|
                \_ ->
                    Int64 0x510E527F 0xADE682D1
                        |> Int64.shiftRightZfBy 14
                        |> Int64.toHex
                        |> Expect.equal (Int64 0x00014439 0x49FEB79A |> Int64.toHex)
            , test "shiftLeftBy 18" <|
                \_ ->
                    Int64 0x510E527F 0xADE682D1
                        |> Int64.shiftLeftBy (64 - 14)
                        |> Int64.toHex
                        |> Expect.equal (Int64 0x0B440000 0x00 |> Int64.toHex)
            , test "or" <|
                \_ ->
                    Int64.or (Int64 0x00014439 0x49FEB79A) (Int64 0x0B440000 0x00)
                        |> Int64.toHex
                        |> Expect.equal (Int64 0x0B454439 0x49FEB79A |> Int64.toHex)
            ]
        , describe "rotateRightBy 18 tests"
            [ test "rotateRightBy 18" <|
                \_ ->
                    Int64 0x510E527F 0xADE682D1
                        |> Int64.rotateRightBy 18
                        |> Int64.toHex
                        |> Expect.equal (Int64 0xA0B45443 0x949FEB79 |> Int64.toHex)
            , test "shiftRightBy 18" <|
                \_ ->
                    Int64 0x510E527F 0xADE682D1
                        |> Int64.shiftRightZfBy 18
                        |> Int64.toHex
                        |> Expect.equal (Int64 0x1443 0x949FEB79 |> Int64.toHex)
            , test "shiftLeftBy 18" <|
                \_ ->
                    Int64 0x510E527F 0xADE682D1
                        |> Int64.shiftLeftBy (64 - 18)
                        |> Int64.toHex
                        |> Expect.equal (Int64 0xA0B44000 0x00 |> Int64.toHex)
            ]
        , describe "rotateRightBy 41 tests"
            [ test "rotateRightBy 41" <|
                \_ ->
                    Int64 0x510E527F 0xADE682D1
                        |> Int64.rotateRightBy 41
                        |> Int64.toHex
                        |> Expect.equal (Int64 0x3FD6F341 0x68A88729 |> Int64.toHex)
            , test "shiftRightBy 41" <|
                \_ ->
                    Int64 0x510E527F 0xADE682D1
                        |> Int64.shiftRightZfBy 41
                        |> Int64.toHex
                        |> Expect.equal (Int64 0x00 0x00288729 |> Int64.toHex)
            , test "shiftLeftBy 41" <|
                \_ ->
                    Int64 0x510E527F 0xADE682D1
                        |> Int64.shiftLeftBy (64 - 41)
                        |> Int64.toHex
                        |> Expect.equal (Int64 0x3FD6F341 0x68800000 |> Int64.toHex)
            ]
        ]
