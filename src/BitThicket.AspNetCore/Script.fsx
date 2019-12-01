#load "../../.paket/load/netcoreapp3.0/FParsec.fsx"

open FParsec

let testParser p str =
    match run p str with
    | Success(result, _, _)   -> printfn "Success: %A" result
    | Failure(errorMsg, _, _) -> printfn "Failure: %s" errorMsg

let pcomma : Parser<char,unit> = pchar ','
let pquote : Parser<char,unit> = pchar '"'

let pkey : Parser<string,unit> = 
    IdentifierOptions()
    |> identifier

let pvalue : Parser<string,unit> = 
    pquote >>. manySatisfy (fun c -> c <> '"') .>> pquote

let pkvp : Parser<(string*string),unit> =
    pkey .>> pchar '=' .>>.? pvalue

let p = sepBy pkvp pcomma