module TestSha256 exposing (mine, spec)

import Bitwise exposing (..)
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Decode as Decode exposing (Decoder, Step(..))
import Bytes.Encode as Encode
import Expect exposing (Expectation)
import Fuzz exposing (Fuzzer, int, list, string)
import Hex.Convert
import Internal.SHA256 as Internal
import SHA256
import Test exposing (..)


mine =
    test "100 000 as" <|
        \_ ->
            -- String.repeat 1000000 "a" |> SHA224.fromString
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqgalkjgkjdsfkjdfk3i3i3ij"
                |> SHA256.fromString
                |> SHA256.toHex
                |> Expect.equal "bd7ef93f08304fe70fef14aa9fadfd325ad88331d78f23516b7ff826d339cd8b"


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
    , "00000018"
    ]


paddedBlock2 =
    [ "61626364"
    , "62636465"
    , "63646566"
    , "64656667"
    , "65666768"
    , "66676869"
    , "6768696a"
    , "68696a6b"
    , "696a6b6c"
    , "6a6b6c6d"
    , "6b6c6d6e"
    , "6c6d6e6f"
    , "6d6e6f70"
    , "6e6f7071"
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
    , "000001c0"
    ]


spec =
    describe "tests from the spec"
        [ describe "spec example 1"
            [ test "abc" <|
                \_ ->
                    "abc"
                        |> SHA256.fromString
                        |> SHA256.toHex
                        |> Expect.equal "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            , test "pad message" <|
                \_ ->
                    let
                        msg =
                            "abc"
                    in
                    Encode.encode (Encode.string msg)
                        |> Internal.padBuffer (String.length msg)
                        |> Hex.Convert.toString
                        |> Hex.Convert.blocks 8
                        |> List.map String.toLower
                        |> Expect.equal paddedBlock1
            ]
        , describe "spec example 2"
            [ test "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" <|
                \_ ->
                    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
                        |> SHA256.fromString
                        |> SHA256.toHex
                        |> Expect.equal "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
            , test "pad message" <|
                \_ ->
                    let
                        msg =
                            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
                    in
                    Encode.encode (Encode.string msg)
                        |> Internal.padBuffer (String.length msg)
                        |> Hex.Convert.toString
                        |> Hex.Convert.blocks 8
                        |> List.map String.toLower
                        |> Expect.equal paddedBlock2
            ]
        , describe "spec example 3"
            [ test "1 000 000 as" <|
                \_ ->
                    -- String.repeat 1000000 "a" |> SHA224.fromString
                    List.repeat (1000000 // 4) (Encode.unsignedInt32 BE 0x61616161)
                        |> Encode.sequence
                        |> Encode.encode
                        |> SHA256.fromBytes
                        |> SHA256.toHex
                        |> Expect.equal "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
            , test "2 000 000 as" <|
                \_ ->
                    -- String.repeat 1000000 "a" |> SHA224.fromString
                    List.repeat (2000000 // 4) (Encode.unsignedInt32 BE 0x61616161)
                        |> Encode.sequence
                        |> Encode.encode
                        |> SHA256.fromBytes
                        |> SHA256.toHex
                        |> Expect.equal "bcf7f9d1b4311c3352e60502255ce09a6744df84e8f2c89f79c4b5d74933a95a"
            , test "100 000 as" <|
                \_ ->
                    -- String.repeat 1000000 "a" |> SHA224.fromString
                    List.repeat (100000 // 4) (Encode.unsignedInt32 BE 0x61616161)
                        |> Encode.sequence
                        |> Encode.encode
                        |> SHA256.fromBytes
                        |> SHA256.toHex
                        |> Expect.equal "6d1cf22d7cc09b085dfc25ee1a1f3ae0265804c607bc2074ad253bcc82fd81ee"
            , test "500 000 as" <|
                \_ ->
                    -- String.repeat 1000000 "a" |> SHA224.fromString
                    {-
                       List.repeat (100000 // 4) (Encode.unsignedInt32 BE 0x61616161)
                           |> Encode.sequence
                           |> Encode.encode
                           |> SHA256.fromBytes
                    -}
                    String.repeat 100000 "a"
                        |> SHA256.fromString
                        |> SHA256.toHex
                        |> Expect.equal "6d1cf22d7cc09b085dfc25ee1a1f3ae0265804c607bc2074ad253bcc82fd81ee"
            ]
        ]
