/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2021-01-25
   Identifier: 21_Jan
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_2dc0e02fcc1a56c81903905869a396f328813e63eba46f941ff3379430e12d12 {
   meta:
      description = "21_Jan - file 2dc0e02fcc1a56c81903905869a396f328813e63eba46f941ff3379430e12d12.exe"
      author = "Ian Harte - @is_henderson"
      reference = "https://bazaar.abuse.ch/sample/2dc0e02fcc1a56c81903905869a396f328813e63eba46f941ff3379430e12d12/"
      date = "2021-01-25"
      hash1 = "2dc0e02fcc1a56c81903905869a396f328813e63eba46f941ff3379430e12d12"
   strings:
      // These were identified as unique as of 21 Jan 2021 and should be regarded as dynamic
      // Always verify samples returned, do not rely soley on YARA

      $s1 = "[AuToRuN]\\ShEllExECutE=__\\DriveMgr.exe\\UsEAuToPLaY=1" fullword wide
      $s2 = "%s\\%s\\DriveMgr.exe" fullword wide
      $s3 = "%ls\\%d%d.exe" fullword wide
      $s4 = "http://api.wipmania.com/" fullword ascii
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s6 = "/c start __ & __\\DriveMgr.exe & exit" fullword wide
      $s7 = "%s\\autorun.inf" fullword wide
      $s8 = "%ls:Zone.Identifier" fullword wide
      $s9 = "%ls:*:Enabled:%ls"
      $s10 = "12sNWkfRAweJAAc3kw2cRAxcivya6jB6euAp7VVYQgq9Cbj1" fullword ascii wide// Possible BTC Cash address?
      
      $op0 = { 83 c4 08 85 c0 74 07 c7 45 f8 34 67 40 00 68 60 }
      $op1 = { 59 59 c3 8b 65 e8 ff 75 88 ff 15 34 61 40 00 ff }
      $op2 = { 55 8b ec 83 ec 18 c7 45 f0 }
      $op3 = { 66 77 70 72 69 6e 74 66 ?? ?? 03 02 5f 77 66 6f 70 65 6e 00 64 }
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      ( 3 of ($s*) and 1 of ($op*) )
}

