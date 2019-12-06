module Tests

open System
open Swensen.Unquote
open Xunit

open BitThicket.AspNetCore.Authentication

type UnvalidatedSignatureEnvelope with
    static member Default : UnvalidatedSignatureEnvelope =
        { keyId = None; signature = None; algorithm = None;
          created = None; expires = None; headers = None }

(*
    Rules for validation:
     * keyId:
        - required
     * signature
        - required
        - must be valid base64 encoding
     * algorithm
        - optional
        - if different than the algorithm associated with keyId, then error
        - must be from the HTTP Signatures Algorithms Registry, which doesn't exist.
          probably best to use https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#Hash
          instead, although for now only hmac-sha256 is supported.
     * created
        - optional
        - must be a unix timestamp, seconds precision
        - must be in the past (but can be within the skew threshold)
     * expires
        - optional
        - must be a unix timestamp, seconds precision
        - must be in the future (but can be in the skew threshold)
     * headers
        - optional, but if not specified then equivalent to "(created)"
        - lowercased, quoted list of header fields, separated by spaces
        - can be unspecified, but cannot be empty
     
     general:
        * any unknown fields must be ignored
        * any ambiguous fields (such as duplicates of any of the above) must
          result in an error
*)

[<Fact>]
let ``[UnvalidatedSignatureEnvelope] TryParse keyId, empty signature Ok`` () =
    let headerString = """
        keyId="1234",signature=""
    """
    let expected =
        { UnvalidatedSignatureEnvelope.Default with
            keyId = Some "1234"; signature = Some "" }
    test <@ UnvalidatedSignatureEnvelope.TryParse headerString = Ok expected @>

[<Fact>]
let ``[UnvalidatedSignatureEnvelope] TryParse keyId,signature Ok`` () =
    let headerString = """
        keyId="1234",signature="asdf"
    """
    let expected =
        { UnvalidatedSignatureEnvelope.Default with
            keyId = Some "1234"; signature = Some "asdf" }
    test <@ UnvalidatedSignatureEnvelope.TryParse headerString = Ok expected @>

[<Theory>]
[<InlineData(@"keyId=""1234"",signature")>]
let ``[UnvalidatedSignatureEnvelope] TryParse Error`` headerString =
    test <@ match UnvalidatedSignatureEnvelope.TryParse headerString with
            | Ok _ -> false
            | Error _ -> true @>