rule TA505_Get2
{
    meta:
        description = "TA505 Get2 Malware, dll/exe"
        author = "@is_henderson"
        date = "29 December 2020"
        target = "Current variants of TA505 Get2 malware, will be obosolete with next drop" 
    strings:
        $c2 = "https://ms-pipes-service.com/llliil" wide fullword // This WILL change and should be considered optional. 
        $string = "!svARmRpAa,vITDvRavrTDir,AsIalpaEo"
        $b = { 67 65 74 61 6E 64 67 6F 64 6C 6C 5F 57 69 6E 33 32 2E 64 6C 6C } // getandgodll_Win32.dll
    condition:
            uint16(0) == 0x5A4D and ($b and $string) or $c2 and filesize < 1MB
}
