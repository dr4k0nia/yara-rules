import "dotnet"

rule msil_suspicious_use_of_strreverse {
    meta:
        /* 
          This combination of imports and usage of StrReverse appears often
          in .NET crypters and malware trying to evade static string analysis
        */
        description = "Detects mixed use of Microsoft.CSharp and VisualBasic to use StrReverse"
        author = "dr4k0nia"
        version = "1.0"
        date = "01/31/2023"
        hash = "02ce0980427dea835fc9d9eed025dd26672bf2c15f0b10486ff8107ce3950701"
    strings:
        $csharp = "Microsoft.CSharp"
        $vbnet = "Microsoft.VisualBasic"
        $strreverse = "StrReverse"
    condition:
        dotnet.is_dotnet
        and $csharp
        and $vbnet
        and $strreverse
}
