module Tests

open System
open Swensen.Unquote
open Xunit

open BitThicket.AspNetCore.Authentication

type UnvalidatedSignatureEnvelope with
    static member Default : UnvalidatedSignatureEnvelope =
        { keyId = None; signature = None; algorithm = None;
          created = None; expires = None; headers = None }

[<Fact>]
let ``[UnvalidatedSignatureEnvelope] TryParse Ok`` () =
    let headerString = """
        keyId="1234",signature=""
    """
    let expected =
        { UnvalidatedSignatureEnvelope.Default with
            keyId = Some "1234"; signature = Some "" }
    test <@ UnvalidatedSignatureEnvelope.TryParse headerString = Ok expected @>

[<Theory>]
[<InlineData(@"keyId=""1234"",signature")>]
let ``[UnvalidatedSignatureEnvelope] TryParse Error`` headerString =
    test <@ match UnvalidatedSignatureEnvelope.TryParse headerString with
            | Ok _ -> false
            | Error _ -> true @>