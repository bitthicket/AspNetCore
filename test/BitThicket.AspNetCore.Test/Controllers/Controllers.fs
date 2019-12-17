namespace BitThicket.AspNetCore.Test.Controllers

open Microsoft.AspNetCore.Authorization
open Microsoft.AspNetCore.Mvc
open Microsoft.Extensions.Logging

type HomeController(logger:ILogger<HomeController>) =
    inherit Controller()

    [<Authorize>]
    member __.Index(?id:int) =
        JsonResult("ok")