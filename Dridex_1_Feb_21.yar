rule Jbox_Dridex_1_Feb_2021 {
   meta:
      
      description = "Dridex - Updated"
      author = "Ian Harte - @is_henderson"
      reference = "https://www.joesandbox.com/analysis/346906/0/html"
      date = "2021-02-01"
      hash1 = "4b2a101f9e7e0119409b6faae798c1e9fada080f055509f477c598365e1f6618"
   
   strings:
   	  
   	  $drp = "loaddll32.exe" fullword wide
      
      // C2(Command & Control) will change, current for 4b2a101f9e7e0119409b6faae798c1e9fada080f055509f477c598365e1f6618 only
      $ip1 = "77.220.64.131:443" ascii
      $ip2 = "5.196.204.251:5037" ascii
      $ip3 = "192.99.41.136:981", ascii
      $ip4 = "24.229.3.146:4664" ascii
      
      $s1 = "c:\\CoolFamily\\NounWhat\\MostKill\\ReadyCity\\lost.pdb" fullword ascii
      $s2 = "lost.dll" fullword ascii
      $s3 = "<command:command xmlns:maml=\"http://schemas.microsoft.com/maml/2004/10\" xmlns:command=\"http://schemas.microsoft.com/maml/dev/" ascii
      $s4 = "<!-- v 1.1.0.9 -->" fullword ascii
      $s5 = " &quot;get-eventlog -list&quot;." fullword ascii
      $s6 = " &quot;get-psdrive | format name, description&quot;. " fullword ascii
      
      $op0 = { e8 83 f0 ff ff 59 59 8b 75 08 8d 34 f5 70 f0 47 }
      $op1 = { 3b c3 74 17 39 18 75 13 50 e8 8e ed ?? ?? ff b6 }
      $op2 = { 3b c3 74 17 ( 39 18 | 75 13 ) 50 e8 6d ed ff ff }
      $op3 = { 75 6e 57 68 61 74 5c 4d 6f 73 74 4b 69 6c 6c 5c }  //unWhat\MostKill\
      $op4 = { 52 65 61 64 79 43 69 74 79 5c 6c 6f 73 74 2e 70 } // ReadyCity\lost.p
      $op5 = { 6c 6f 73 74 2e 64 6c 6c 00 53 68 6f 70 73 65 6c } // lost.dll.Shopsel
      

   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 5 of them
}
