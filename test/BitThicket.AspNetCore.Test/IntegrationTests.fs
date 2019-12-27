module IntegrationTests

open System
open System.Collections.Generic
open System.Net
open System.Net.Http.Headers
open System.Security.Cryptography
open System.Text
open System.Text.RegularExpressions
open System.Threading.Tasks
open Microsoft.AspNetCore.Authorization
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.AspNetCore.Hosting.Server
open Microsoft.AspNetCore.Http
open Microsoft.AspNetCore.TestHost
open Microsoft.Extensions.Configuration
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Logging
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.Options
open Microsoft.Extensions.Primitives
open FSharp.Control.Tasks.V2.ContextInsensitive
open Divergic.Logging.Xunit
open Swensen.Unquote
open Xunit
open Xunit.Abstractions

// SUT
open BitThicket.AspNetCore.Authentication

/// simple auth header value generator.  keyId and secret required; fields required.
/// fields should not include "keyId" or "signature"
/// values should include both field values and header values (other than keyId and signature).
let makeAuthHeaderValue (out:ITestOutputHelper) keyId secret (fields:seq<string>) (headers:seq<string> option) (values:IDictionary<string,string>) =
    let signatureString = 
        match headers with
        | None -> 
            sprintf "(created): %s" values.["(created)"]
        | Some headerNames ->
            headerNames
            |> Seq.fold 
                (fun (buf:StringBuilder) headerName ->
                    buf.Append(headerName).Append(": ").AppendLine(values.[headerName]))
                (StringBuilder())
            |> (fun sb -> sb.ToString())
        |> (fun s -> s.Trim())

    out.WriteLine("signature string: '{0}'", signatureString)

    use hash = new HMACSHA256(secret)
    let signature = hash.ComputeHash(Encoding.UTF8.GetBytes(signatureString))
    let encodedSignature = Convert.ToBase64String(signature)

    let authHeaderBuilder = 
        fields
        |> Seq.fold
               (fun (sb:StringBuilder) field ->
                   sb.AppendFormat(",{0}=\"{1}\"", field, values.[field]))
            (StringBuilder(sprintf "keyId=\"%s\"" keyId))
    
    headers 
    |> Option.map 
        (fun headerNames ->
            headerNames
            |> Seq.fold 
                    (fun (sb:StringBuilder) name ->
                        sb.Append(" ").Append(name))
                    (StringBuilder())
            |> (fun sb -> authHeaderBuilder.AppendFormat(",headers=\"{0}\"", sb.ToString().Trim())))
    |> ignore

    authHeaderBuilder.AppendFormat(",signature=\"{0}\"", encodedSignature).ToString().Trim()

type IntegrationTests(output:ITestOutputHelper) =

    [<Fact>]
    [<Trait("Category", "Integration")>]
    member __.``signature authentication failure against bare request delegate``() = task {
        let builder = 
            WebHostBuilder()
                .ConfigureServices(
                    fun services -> 
                        services
                            .AddDistributedMemoryCache()
                            .AddAuthentication("Signature")
                            .AddScheme<SignatureAuthenticationOptions, SignatureAuthenticationHandler>("Signature", 
                                fun (opts:SignatureAuthenticationOptions) -> 
                                    opts.Realm <- "Test"
                                    // no need to configure a secret provider; the default will return None
                                    )
                        |> ignore)
                .ConfigureLogging(
                    fun logging ->
                        logging
                            .AddFilter(fun _ -> true)
                            .AddXunit(output)
                        |> ignore)
                .Configure(
                    fun app ->
                        app.UseAuthentication() |> ignore
                        app.Run(fun context -> 
                            task {
                                if Seq.isEmpty context.User.Claims then
                                    context.Response.StatusCode <- 401
                                    context.Response.Headers.["WWW-Authenticate"] <- StringValues("Signature")
                                else
                                    do! context.Response.WriteAsync("Hello World")
                            } :> Task))
        use server = new TestServer(builder)

        let! response = server.CreateClient().GetAsync("/")
        test <@ response.StatusCode = HttpStatusCode.Unauthorized @>
    }

    static member private GetAuthHeaderValues() : seq<obj[]> = seq {
        let secret1 = Guid.NewGuid().ToByteArray()
        let secret2 = Guid.NewGuid().ToByteArray()
        let secret3 = Guid.NewGuid().ToByteArray()
        let headers3 = dict [
            ("x-special-header", "7")
        ]

        // simplest signature; keyId+created only
        yield [| 
            secret1
            (fun (out:ITestOutputHelper) -> 
                let createdTs = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()
                makeAuthHeaderValue out "test-1" secret1 ["created"] None 
                    (dict [ ("(created)", createdTs)
                            ("created", createdTs) ]))
            None
            true
        |]

        // (created) (expires)
        yield [|
            secret2
            (fun (out:ITestOutputHelper) ->
                let createdDto = DateTimeOffset.UtcNow
                let createdTs = createdDto.ToUnixTimeSeconds().ToString()
                let expiresTs = createdDto.AddMinutes(10.0).ToUnixTimeSeconds().ToString()
                let fields = ["created";"expires"]
                let headers = ["(created)"; "(expires)"] 
                              |> seq |> Some
                let values = dict [
                    ("created", createdTs)
                    ("expires", expiresTs)
                    ("(created)", createdTs)
                    ("(expires)", expiresTs)
                ]
                makeAuthHeaderValue out "test-2" secret2 fields headers values)
            None
            true
        |]

        // basic header usage
        let headers3 = dict [
            ("X-Special-Header", "7")
        ]
        yield [|
            secret3
            (fun (out:ITestOutputHelper) ->
                let created = DateTimeOffset.UtcNow
                let fields = ["created"]
                let headers = 
                    ["(created)"; "x-special-header"]
                    |> seq |> Some
                let values = dict [
                    ("x-special-header", headers3.["X-Special-Header"])
                    ("created", created.ToUnixTimeSeconds().ToString())
                    ("(created)", created.ToUnixTimeSeconds().ToString())
                ]
                makeAuthHeaderValue out "test-3" secret3 fields headers values)
            Some headers3
            true
        |]
        // parser failiure (test-4)
        yield [|
            Guid.Empty.ToByteArray()
            (fun (out:ITestOutputHelper) -> 
                out.WriteLine("Using unparsable header")
                "hahahahaha")
            None
            false
        |]

        // totally bogus signature
        yield [|
            Guid.Empty.ToByteArray()
            (fun (out:ITestOutputHelper) -> 
                out.WriteLine("Using bogus signature")
                @"keyId=""test-5"",signature=""hahahaha""")
            None
            false
        |]

        let headers5 = dict [
            ("X-Unused-Header", "")
        ]
        let secret5 = Guid.NewGuid().ToByteArray()
        yield [|
            secret5
            (fun (out:ITestOutputHelper) ->
                let created = DateTimeOffset.UtcNow
                let fields = ["created"]
                let headers = ["(created)"; "x-special-header"]
                              |> seq |> Some
                let values = dict [
                    ("x-special-header", "7")
                    ("created", created.ToUnixTimeSeconds().ToString())
                    ("(created)", created.ToUnixTimeSeconds().ToString())
                ]
                makeAuthHeaderValue out "test-5" secret5 fields headers values)
            Some headers5
            false
        |]
    }

    [<Theory>]
    [<Trait("Category", "Integration")>]
    [<MemberData("GetAuthHeaderValues")>]
    member __.``signature authentication success against bare request delegate``(clientSecret:byte[], 
                                                                                 authHeaderGenerator:ITestOutputHelper -> string, 
                                                                                 headers:IDictionary<string,string> option, 
                                                                                 success:bool) = task {
        let objIdGen = System.Runtime.Serialization.ObjectIDGenerator()
        let builder = 
            WebHostBuilder()
                .ConfigureServices(
                    fun services -> 
                        services
                            .AddDistributedMemoryCache()
                            .AddAuthentication("Signature")
                                .AddScheme<SignatureAuthenticationOptions, SignatureAuthenticationHandler>("Signature", 
                                    fun (opts:SignatureAuthenticationOptions) -> 
                                        let stack = Exception().StackTrace
                                        let objId = objIdGen.GetId(opts,ref false)
                                        output.WriteLine("Configuring options [{0}] at\n{1}", objId, stack)

                                        opts.Realm <- "Test"
                                        opts.ClientSecretProvider <- 
                                            { new IClientSecretProvider with
                                                member __.GetClientSecretAsync(_) =
                                                    Some clientSecret |> Task.FromResult } )
                        |> ignore)
                .ConfigureLogging(
                    fun logging ->
                        logging
                            .AddFilter(fun _ -> true)
                            .AddXunit(output)
                        |> ignore)
                .Configure(
                    fun app ->
                        app.UseAuthentication() |> ignore
                        app.Run(fun context -> 
                            task {
                                if Seq.isEmpty context.User.Claims then
                                    context.Response.StatusCode <- 401
                                    context.Response.Headers.["WWW-Authenticate"] <- StringValues("Signature")
                                else
                                    do! context.Response.WriteAsync("Hello World")
                            } :> Task) )
        
        use server = new TestServer(builder)
        let client = server.CreateClient()
        
        let authHeaderValue = authHeaderGenerator(output)
        output.WriteLine("Authorization header value: {0}", authHeaderValue)
        client.DefaultRequestHeaders.Authorization <- AuthenticationHeaderValue("Signature", authHeaderValue)

        // set headers required by signature
        match headers with
        | Some headerList ->
            for headerPair in headerList do
                client.DefaultRequestHeaders.Add(headerPair.Key, headerPair.Value)
        | _ -> ()

        let! response = client.GetAsync("/")
        if success then 
            <@ response.StatusCode = HttpStatusCode.OK @>
        else 
            <@ response.StatusCode <> HttpStatusCode.OK @>
        |> test
    }

    [<Fact>]
    [<Trait("Category", "Integration")>]
    member __.``signature authentication failure against simple MVC controller``() = task {
        let builder =
            WebHostBuilder()
                .ConfigureServices(
                    fun services ->
                        services
                            .AddDistributedMemoryCache()
                            .AddAuthentication("Signature")
                                .AddScheme<SignatureAuthenticationOptions, SignatureAuthenticationHandler>("Signature",
                                    fun (opts:SignatureAuthenticationOptions) -> opts.Realm <- "Test")
                        |> ignore
                        
                        services.AddMvc(fun mvc -> mvc.EnableEndpointRouting <- false)
                        |> ignore)
                .ConfigureLogging(
                    fun logging ->
                         logging
                            .AddFilter(fun _ -> true)
                            .AddXunit(output)
                         |> ignore)
                .Configure(
                    fun app ->
                        app.UseAuthentication() |> ignore
                        app.UseMvcWithDefaultRoute() |> ignore)

        use server = new TestServer(builder)

        let! response = server.CreateClient().GetAsync("/")
        test <@ response.StatusCode = HttpStatusCode.Unauthorized @>
    }
