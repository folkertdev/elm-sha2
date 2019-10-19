# SHA2 

A fast `elm/bytes`-based implementation of sha-2 (sha224, sha256, sha385, and sha512).

This package is built for speed. Existing packages were built before `elm-bytes` was published, and have to work around the lack of native support for compact arrays.
The code has been validated against examples from the spec and test cases from the [CAVS](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program).

The primary hash functions are sha256 and sha512. The other two are derivatives that only use some of the bytes. 

## Examples 


```elm
import SHA256
import SHA512
import Bytes
import Bytes.Encode as Encode

buffer : Bytes.Bytes
buffer = 
    [0x00, 0xFF, 0xCE, 0x35, 0x74]
        |> List.map Encode.unsignedInt8
        |> Encode.sequence
        |> Encode.encode


digest1 : SHA256.Digest
digest1 = SHA256.fromString "string"

digest2 : SHA512.Digest
digest2 = SHA512.fromBytes buffer


SHA256.toHex digest1
--> "473287f8298dba7163a897908958f7c0eae733e25d2e027992ea2edc9bed2fa8"

SHA512.toBase64 digest2
--> "cLkMLYLshiRHyde6ysrK0/pzRt6MzfCoNeMvXIWd/IX01zUqk5RbLAiMo5sHv33A6h8HSbIsR5CDfCUWPwKuag=="
```

**Example Files**

* [Hash a `File`](https://github.com/folkertdev/elm-sha2/blob/master/benchmark/FileUpload.elm)

## Performance notes

On my machine, with a 3Mb file

* sha256 takes ~400ms
* sha512 takes ~1500ms

Why is this package faster than other current elm packages? Mainly because the usage of `elm/bytes`, which provides more compact storage and faster decoding than working with for instance a `List Int`.
But there are some other tricks, like minimizing allocation and manual inlining of small functions. I plan to write a blog post about this. 

But objectively, this is not very fast. C implementations can go much faster. As far as I can see, this has to do with inlining again. The code elm generates contains many function calls, which are known to be expensive.
For instance in the sha256 case, the `A2`, `A3` etc wrappers take 20% of total execution time, while they could technically be removed. When the elm compiler gets better support for inlining, the performance of this package should improve further (especially sha521).

Sha512 is also slower because it simulates unsigned 64-bit integers (particularly their overflow behavior). Custom arithmetic operators are slower than the browser's buit-in ones.

## Acknoledgements

The code is based on [TSFoster/elm-sha1](https://package.elm-lang.org/packages/TSFoster/elm-sha1/latest/) and a PR I made to it. The documentation was adapted from there too.
