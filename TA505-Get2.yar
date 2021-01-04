rule TA505_Get2
{
    meta:
        description = "TA505 Get2 Malware, dll/exe"
        author = "@is_henderson"
        date = "29 December 2020"
        target = "Current variants of TA505 Get2 malware, will be obosolete with next drop" 
    strings:
        //$c2 = "https://ms-pipes-service.com/llliil" wide fullword // This WILL change and should be considered optional.
        $s1 = "!svARmRpAa,vITDvRavrTDir,AsIalpaEo" // unique at time of writing
        $s2 = "slisatsbfIppooavv" // found in export
        $b = { 67 65 74 61 6E 64 67 6F 64 6C 6C 5F 57 69 6E 33 32 2E 64 6C 6C } // getandgodll_Win32.dll, which appears in older variants as well.
    condition:
            uint16(0) == 0x5A4D and ($s1 and $s2) or $b and filesize < 1MB
}
