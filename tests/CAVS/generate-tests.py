from textwrap import wrap

module_template =  """module CAVS.CAVS224 exposing (suite)

import Bitwise
import Expect
import SHA224
import Test exposing (describe, test)
import Bytes.Encode as Encode


suite : Test.Test
suite =
    let
        byteList = Encode.encode << Encode.sequence << List.map Encode.unsignedInt8 

        testSHA224 index hex bytes =
            test (String.fromInt index ++ " " ++ Debug.toString bytes) <|
                \_ ->
                    bytes 
                        |> byteList 
                        |> SHA224.fromBytes
                        |> SHA224.toHex
                        |> Expect.equal hex
    in
    describe "cavs test suite"
        [ describe "long" [{tests_long} ]
        , describe "short" [{tests_short} ]
        ]
"""

def formatHex(int32):
    # return '\\u{' + int32 +"}"
    return '0x' + int32


def formatHexes(int32s):
    return "[" + ", ".join(formatHex(v) for v in int32s) + "]"
    # return "\"" + "".join(formatHex(v) for v in int32s) + "\""



names = ["SHA224LongMsg","SHA224ShortMsg" ] 
 
def process_file(name):
    with open("responses/" + name + ".rsp") as f:
        is_short = True 

        cut = 2 if is_short else 3

        content = f.read().split("\n\n")[cut:]

        tests = []

        for item in enumerate(v.split("\n") for v in content):
            if is_short:
                try:
                    (i, (length_, msg, md, *_)) = item
                except ValueError:
                    continue

                else:
                    length = int(length_[6:])

                    hexDigits = [ v.zfill(2) for v in wrap(msg[6:], 2) ][:length]

            else: 
                try:
                    (i, (msg, md, *_)) = item
                except ValueError:
                    continue
                else:
                    hexDigits = [ v.zfill(4) for v in wrap(msg[6:], 2) ]

            answer = md[5:] 
            template = """testSHA224 {}  "{}" {} """.format(i, answer, formatHexes(hexDigits))

            tests.append(template)
            
        return "\n    ,".join(tests)

if __name__ == '__main__':
    env = { "tests_monte" : process_file("SHA224Monte") ,  "tests_long" : process_file("SHA224LongMsg") ,  "tests_short" : process_file("SHA224ShortMsg") }

    with open("CAVS.elm", "w+") as f:
        f.write(module_template.format(**env))
