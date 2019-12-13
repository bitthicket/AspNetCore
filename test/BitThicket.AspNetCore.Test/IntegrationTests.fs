module IntegrationTests

open System
open System.Net
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.AspNetCore.Hosting.Server
open Microsoft.AspNetCore.TestHost
open Microsoft.Extensions.Configuration
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.Options
open FSharp.Control.Tasks
open Swensen.Unquote
open Xunit

// SUT
open BitThicket.AspNetCore.Authentication

[<Fact>]
[<Trait("Category", "Integration")>]
let ``signature authenticated request to root``() = task {
    let builder = 
        WebHostBuilder()
            .ConfigureServices(
                fun services -> 
                    services.AddAuthentication("Signature")
                        .AddScheme<SignatureAuthenticationOptions, SignatureAuthenticationHandler>("Signature", 
                            fun (opts:SignatureAuthenticationOptions) -> 
                                opts.Realm <- "Test"
                                opts.ClientSecretProvider <- 
                    |> ignore)
                        
            .Configure(
                fun app -> 
                    app |> ignore)

    use server = new TestServer(builder)

    let! response = server.CreateClient().GetAsync("/")
    printfn "testserver response: %A" response
    test <@ response.StatusCode = HttpStatusCode.NotFound @>
}