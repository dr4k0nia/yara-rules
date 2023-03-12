import "dotnet"

/* 
Rule to detect script kiddie antidump code, often used by malware
This anti dump code is unstable and only works for 32bit compiled binaries
*/
rule msil_susp_obf_antidump {
    meta:
        author = "dr4k0nia"
        version = "1.0"
        date = "12/03/2023"
        hash = "ef7bb2464a2b430aa98bd65a1a40b851b57cb909ac0aea3e53729c0ff900fa42"
    strings:
        // Functions required by the antidump
        $import0 = "ZeroMemory"
        $import1 = "VirtualProtect"
        $importt2 = "GetCurrentProcess"

        // Hardcoded offset arrays used by the antidump 
        
        // Hex of PE.SectionTabledWords array
        $array0 = {1D 8D 9E 00 00 01 25 D0 67 00 00 04 28 CF 01 00 0A 80 84 00 00 04}
        // Hex of PE.Words array
        $array1 = {1F 0C 8D 9E 00 00 01 25 D0 65 00 00 04 28 CF 01 00 0A 80 86 00 00 04}
        // Hex of PE.dWords array
        $array2 = {1F 1B 8D 9E 00 00 01 25 D0 66 00 00 04 28 CF 01 00 0A 80 87 00 00 04}
    condition:
        uint16(0) == 0x5a4d
        and dotnet.is_dotnet
        and all of($import*)
        and all of($array*)
}
