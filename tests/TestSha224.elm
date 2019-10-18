module TestSha224 exposing (..)

import Bitwise exposing (..)
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Decode as Decode exposing (Decoder, Step(..))
import Bytes.Encode as Encode
import Expect exposing (Expectation)
import Fuzz exposing (Fuzzer, int, list, string)
import Hex.Convert
import SHA224
import Test exposing (..)


spec =
    describe "tests from the spec"
        [ describe "spec example 1"
            [ test "abc" <|
                \_ ->
                    "abc"
                        |> SHA224.fromString
                        |> SHA224.toHex
                        |> Expect.equal "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
            ]
        , describe "spec example 2"
            [ test "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" <|
                \_ ->
                    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
                        |> SHA224.fromString
                        |> SHA224.toHex
                        |> Expect.equal "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
            ]
        , describe "spec example 3"
            [ test "as" <|
                \_ ->
                    -- String.repeat 1000000 "a" |> SHA224.fromString
                    List.repeat 1000000 (Encode.unsignedInt8 97)
                        |> Encode.sequence
                        |> Encode.encode
                        |> SHA224.fromBytes
                        |> SHA224.toHex
                        |> Expect.equal "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"
            ]
        ]
