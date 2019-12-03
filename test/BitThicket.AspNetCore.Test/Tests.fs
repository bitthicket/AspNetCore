module Tests

open System
open System.Security.Cryptography
open System.Text
open System.Threading.Tasks
open Swensen.Unquote
open Xunit

open BitThicket.AspNetCore.Authentication

type UnvalidatedSignatureEnvelope with
    static member Default : UnvalidatedSignatureEnvelope =
        { keyId = None; signature = None; algorithm = None;
          created = None; expires = None; headers = None }

type IdentityClientSecretProvider(secret:byte[] option) =
    interface IClientSecretProvider<string> with
        member __.GetClientSecretAsync _ = Task.FromResult(secret)

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

[<Fact>]
let ``[SignatureHelpers] validateSignatureEnvelope with minimal valid envelope Ok``() =
    let secret = Guid.NewGuid().ToByteArray()
    let offset = DateTimeOffset.UtcNow
    let signatureString = sprintf "created: %d" (offset.ToUnixTimeSeconds())
    
    use hmac = new HMACSHA256(secret)
    let signature = hmac.ComputeHash(Encoding.UTF8.GetBytes(signatureString))
    let base64sig = Convert.ToBase64String(signature)

    let envelope : UnvalidatedSignatureEnvelope = 
        { keyId = Some "1234"
          signature = Some base64sig
          algorithm = None
          created = offset.ToUnixTimeSeconds().ToString() |> Some
          expires = None
          headers = None }

    let expected = 
        { keyId = "1234"
          signature = signature
          algorithm = None
          created =  offset.ToUnixTimeSeconds() |> Some
          expires = None
          headers = None}

    let secretProvider = IdentityClientSecretProvider(Some secret)
    let options = SignatureAuthenticationOptions(secretProvider)

    test <@ SignatureHelpers.validateSignatureEnvelope options envelope = Ok expected @>

[<Theory>]
[<InlineData("keyId")>]
[<InlineData("signature")>]
let ``[SignatureHelpers] validateSignatureEnvelope missing parameter Error``(param:string) =
    let offset = DateTimeOffset.UtcNow
    let secret = Guid.NewGuid().ToByteArray()
    let offset = DateTimeOffset.UtcNow
    let signatureString = sprintf "created: %d" (offset.ToUnixTimeSeconds())
    
    use hmac = new HMACSHA256(secret)
    let signature = hmac.ComputeHash(Encoding.UTF8.GetBytes(signatureString))
    let base64sig = Convert.ToBase64String(signature)

    let mutable envelope : UnvalidatedSignatureEnvelope = 
        { keyId = Some "1234"
          signature = Some base64sig
          algorithm = None
          created = offset.ToUnixTimeSeconds().ToString() |> Some
          expires = None
          headers = None }

    envelope <- 
        match param with
        | "keyId" -> { envelope with keyId = None }
        | "signature" -> { envelope with signature = None }
        | x -> failwithf "bad test; %s is not a required parameter" x

    let secretProvider = IdentityClientSecretProvider(Some secret)
    let options = SignatureAuthenticationOptions(secretProvider)

    test <@ SignatureHelpers.validateSignatureEnvelope options envelope = (RequiredParametersMissing [param] |> Error) @>

[<Fact>]
let ``[SignatureHelpers] validateSignatureEnvelope with invalid algorithm Error``() =
    let secret = Guid.NewGuid().ToByteArray()
    let offset = DateTimeOffset.UtcNow
    let signatureString = sprintf "created: %d" (offset.ToUnixTimeSeconds())
    
    use hmac = new HMACSHA256(secret)
    let signature = hmac.ComputeHash(Encoding.UTF8.GetBytes(signatureString))
    let base64sig = Convert.ToBase64String(signature)

    let envelope : UnvalidatedSignatureEnvelope = 
        { keyId = Some "1234"
          signature = Some base64sig
          algorithm = Some "nonesense"
          created = offset.ToUnixTimeSeconds().ToString() |> Some
          expires = None
          headers = None }

    let secretProvider = IdentityClientSecretProvider(Some secret)
    let options = SignatureAuthenticationOptions(secretProvider)

    test <@ SignatureHelpers.validateSignatureEnvelope options envelope = Error InvalidAlgorithm @>

[<Fact>]
let ``[SignatureHelpers] validateSignatureEnvelope with invalid created timestamp Error``() =
    let secret = Guid.NewGuid().ToByteArray()
    let offset = DateTimeOffset.UtcNow
    let signatureString = sprintf "created: %d" (offset.ToUnixTimeSeconds())
    
    use hmac = new HMACSHA256(secret)
    let signature = hmac.ComputeHash(Encoding.UTF8.GetBytes(signatureString))
    let base64sig = Convert.ToBase64String(signature)

    let envelope : UnvalidatedSignatureEnvelope = 
        { keyId = Some "1234"
          signature = Some base64sig
          algorithm = None
          created = Some "x"
          expires = None
          headers = None }

    let secretProvider = IdentityClientSecretProvider(None)
    let options = SignatureAuthenticationOptions(secretProvider)

    test <@ SignatureHelpers.validateSignatureEnvelope options envelope = Error (InvalidCreatedTimestamp "not a valid unix timestamp") @>