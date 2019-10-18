module TestSha384 exposing (..)

import Bitwise exposing (..)
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Decode as Decode exposing (Decoder, Step(..))
import Bytes.Encode as Encode
import Expect exposing (Expectation)
import Fuzz exposing (Fuzzer, int, list, string)
import Hex.Convert
import SHA384
import Test exposing (..)


spec =
    describe "tests from the spec"
        [ describe "spec example 1"
            [ test "abc" <|
                \_ ->
                    "abc"
                        |> SHA384.fromString
                        |> SHA384.toHex
                        |> Expect.equal "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
            ]
        , describe "spec example 2"
            [ test "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" <|
                \_ ->
                    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
                        |> SHA384.fromString
                        |> SHA384.toHex
                        |> Expect.equal "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
            ]
        ]
