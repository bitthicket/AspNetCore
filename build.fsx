#r "paket:
nuget Fake.DotNet.Cli
nuget Fake.DotNet.Paket
nuget Fake.IO.FileSystem
nuget Fake.Core.Target //"
#load ".fake/build.fsx/intellisense.fsx"

open Fake.Core
open Fake.DotNet
open Fake.IO
open Fake.IO.FileSystemOperators
open Fake.IO.Globbing.Operators
open Fake.Core.TargetOperators

Target.initEnvironment ()

Target.create "Clean" (fun _ ->
    !! "src/**/bin"
    ++ "src/**/obj"
    |> Shell.cleanDirs 
)

Target.create "PackageInstall" (fun _ ->
    DotNet.exec id "paket" "install"
    |> ignore)

Target.create "Build" (fun _ ->
    !! "src/**/*.*proj"
    |> Seq.iter (DotNet.build id)
)

Target.create "BuildPackage" (fun _ ->
    Paket.pack 
        (fun p ->
            { p with
                ToolType = ToolType.CreateLocalTool()
                BuildConfig = "Release"
                ProjectUrl = "src/BitThcket.AspNetCore.fsproj" }))

Target.create "PushPackage" (fun _ ->
    Paket.push 
        (fun p ->
            { p with
                ToolType = ToolType.CreateLocalTool() } ))


"PackageInstall"
  ==> "Build"

Target.create "All" ignore

"Clean"
  ==> "Build"
  ==> "BuildPackage"
  ==> "All"

Target.runOrDefault "All"
