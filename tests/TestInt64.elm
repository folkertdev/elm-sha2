module TestInt64 exposing (..)

import Expect exposing (Expectation)
import Fuzz exposing (Fuzzer, int, list, string)
import Int64 exposing (Int64(..))
import Test exposing (..)


maxInt64 =
    Int64 0xFFFFFFFF 0xFFFFFFFF


y =
    Int64 0x01 0xFFFFFFFF


suite : Test
suite =
    describe "Int64"
        [ test "overflow 1" <|
            \_ ->
                Int64.add maxInt64 (Int64 0x01 0xFFFFFFFF)
                    |> Int64.toHex
                    |> Expect.equal (Int64 0x01 0xFFFFFFFE |> Int64.toHex)
        , test "overflow 2" <|
            \_ ->
                Int64.add maxInt64 maxInt64
                    |> Int64.toHex
                    |> Expect.equal (Int64 0xFFFFFFFF 0xFFFFFFFE |> Int64.toHex)
        , test "overflow 3" <|
            \_ ->
                Int64.add maxInt64 (Int64 0 1)
                    |> Int64.toHex
                    |> Expect.equal (Int64 0 0 |> Int64.toHex)
        , test "overflow 4" <|
            \_ ->
                Int64.add y y
                    |> Int64.toHex
                    |> Expect.equal (Int64 0x03 0xFFFFFFFE |> Int64.toHex)
        , test "overflow 5" <|
            \_ ->
                Int64.add (Int64 0 42) (Int64 0 42)
                    |> Int64.toHex
                    |> Expect.equal (Int64 0 84 |> Int64.toHex)
        , test "overflow 6" <|
            \_ ->
                Int64.add (Int64 1 0xFFFFFFFF) (Int64 0xFFFFFFFF 0x00)
                    |> Int64.toHex
                    |> Expect.equal (Int64 0 0xFFFFFFFF |> Int64.toHex)
        ]
