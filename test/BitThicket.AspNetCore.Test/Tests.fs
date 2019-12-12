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
    Rules for validation, from 2.1 and 2.2 of the cavage draft RFC
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

(* 
    parsing tests, no RFC validation involved here
*)
[<Fact>]
[<Trait("Category", "Unit")>]
let ``[UnvalidatedSignatureEnvelope] TryParse keyId, empty signature Ok`` () =
    let headerString = """
        keyId="1234",signature=""
    """
    let expected =
        { UnvalidatedSignatureEnvelope.Default with
            keyId = Some "1234"; signature = Some "" }
    test <@ UnvalidatedSignatureEnvelope.TryParse headerString = Ok expected @>

[<Fact>]
[<Trait("Category", "Unit")>]
let ``[UnvalidatedSignatureEnvelope] TryParse keyId,signature Ok`` () =
    let headerString = """
        keyId="1234",signature="asdf"
    """
    let expected =
        { UnvalidatedSignatureEnvelope.Default with
            keyId = Some "1234"; signature = Some "asdf" }
    test <@ UnvalidatedSignatureEnvelope.TryParse headerString = Ok expected @>

[<Theory>]
[<Trait("Category", "Unit")>]
[<InlineData(@"keyId=""1234"",signature")>]
let ``[UnvalidatedSignatureEnvelope] TryParse Error`` headerString =
    test <@ match UnvalidatedSignatureEnvelope.TryParse headerString with
            | Ok _ -> false
            | Error _ -> true @>

(*
    RFC validation tests.  Draft 12, §2.1
*)
[<Fact>]
[<Trait("Category", "Unit")>]
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
[<Trait("Category", "Unit")>]
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
[<Trait("Category", "Unit")>]
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
[<Trait("Category", "Unit")>]
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

[<Fact>]
[<Trait("Category", "Unit")>]
let ``[SignatureHelpers] validateSignatureEnvelope with future created timestamp Error``() =
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
          created = (offset + TimeSpan.FromHours(1.0)).ToUnixTimeSeconds().ToString() |> Some
          expires = None
          headers = None }

    let secretProvider = IdentityClientSecretProvider(None)
    let options = SignatureAuthenticationOptions(secretProvider)

    test <@ SignatureHelpers.validateSignatureEnvelope options envelope = Error (InvalidCreatedTimestamp "timestamp in the future") @>

[<Fact>]
[<Trait("Category", "Unit")>]
let ``[SignatureHelpers] validateSignatureEnvelope with future created timestamp, but inside skew limit Ok``() =
    let secret = Guid.NewGuid().ToByteArray()
    let offset = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(3.0)
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

    let secretProvider = IdentityClientSecretProvider(None)
    let options = SignatureAuthenticationOptions(secretProvider) // default skew is 5m

    test <@ SignatureHelpers.validateSignatureEnvelope options envelope = Ok expected @>

[<Fact>]
[<Trait("Category", "Unit")>]
let ``[SignatureHelpers] validateSignatureEnvelope with invalid expires timestamp Error``() =
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
          created = None
          expires = Some "x"
          headers = None }

    let secretProvider = IdentityClientSecretProvider(None)
    let options = SignatureAuthenticationOptions(secretProvider)

    test <@ SignatureHelpers.validateSignatureEnvelope options envelope = Error (InvalidExpiresTimestamp "not a valid unix timestamp") @>

[<Fact>]
[<Trait("Category", "Unit")>]
let ``[SignatureHelpers] validateSignatureEnvelope with valid expires timestamp Ok``() =
    let secret = Guid.NewGuid().ToByteArray()
    let created = DateTimeOffset.UtcNow
    let expires = DateTimeOffset.UtcNow + TimeSpan.FromMinutes(6.0)
    let signatureString = sprintf "created: %d\nexpires: %d" (created.ToUnixTimeSeconds()) (expires.ToUnixTimeSeconds())

    use hmac = new HMACSHA256(secret)
    let signature = hmac.ComputeHash(Encoding.UTF8.GetBytes(signatureString))
    let base64sig = Convert.ToBase64String(signature)

    let envelope : UnvalidatedSignatureEnvelope = 
        { keyId = Some "1234"
          signature = Some base64sig
          algorithm = None
          created = created.ToUnixTimeSeconds().ToString() |> Some
          expires = expires.ToUnixTimeSeconds().ToString() |> Some
          headers = None }

    let expected = 
        { keyId = "1234"
          signature = signature
          algorithm = None
          created =  created.ToUnixTimeSeconds() |> Some
          expires = expires.ToUnixTimeSeconds() |> Some
          headers = None}

    let secretProvider = IdentityClientSecretProvider(None)
    let options = SignatureAuthenticationOptions(secretProvider)

    test <@ SignatureHelpers.validateSignatureEnvelope options envelope = Ok expected @>