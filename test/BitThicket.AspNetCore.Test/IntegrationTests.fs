module IntegrationTests

open System
open System.Net
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