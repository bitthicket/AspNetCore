module Tests

open System
open Swensen.Unquote
open Xunit

open BitThicket.AspNetCore.Authentication

[<Fact>]
let ``[UnvalidatedSignatureEnvelope] TryParse Ok with empty signature`` () =
    let headerString = """
        keyId="1234",signature=""
    """
    let expected : UnvalidatedSignatureEnvelope = 
        { keyId = Some "1234"
          signature = Some ""
          algorithm = None
          created = None
          expires = None
          headers = None }
    test <@ UnvalidatedSignatureEnvelope.TryParse headerString = Ok expected @>
