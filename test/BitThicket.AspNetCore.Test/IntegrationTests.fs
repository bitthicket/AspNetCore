module IntegrationTests

open System
open System.Net
open System.Threading.Tasks
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting
open Microsoft.AspNetCore.Hosting.Server
open Microsoft.AspNetCore.Http
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
    let clientSecret = Guid.NewGuid().ToByteArray()

    let builder = 
        WebHostBuilder()
            .ConfigureServices(
                fun services -> 
                    services.AddDistributedMemoryCache() |> ignore
                    services.AddAuthentication("Signature")
                        .AddScheme<SignatureAuthenticationOptions, SignatureAuthenticationHandler>("Signature", 
                            fun (opts:SignatureAuthenticationOptions) -> 
                                opts.Realm <- "Test"
                                // opts.ClientSecretProvider <- { new IClientSecretProvider with
                                //                                 member __.GetClientSecretAsync(_) = 
                                //                                     Some clientSecret
                                //                                     |> Task.FromResult }
                                ())
                    |> ignore)
                        
            .Configure(
                fun app ->
                    // app.UseAuthentication() |> ignore
                    app.Run(fun context -> context.Response.WriteAsync("Hello World")) |> ignore
                    app.UseAuthentication()
                    |> ignore)

    use server = new TestServer(builder)

    let! response = server.CreateClient().GetAsync("/")
    printfn "testserver response: %A" response
    test <@ response.StatusCode = HttpStatusCode.NotFound @>
}