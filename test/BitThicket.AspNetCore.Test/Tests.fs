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
type IdentityClientSecretProvider(secret:byte[] option) =
    interface IClientSecretProvider<string> with
        member __.GetClientSecretAsync _ = Task.FromResult(secret)

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