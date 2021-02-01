rule Jbox_Dridex_1_Feb_2021 {
   meta:
      
      description = "Dridex - Updated"
      author = "Ian Harte - Binary Defense Systems"
      reference = "https://www.joesandbox.com/analysis/346906/0/html"
      date = "2021-02-01"
      hash1 = "4b2a101f9e7e0119409b6faae798c1e9fada080f055509f477c598365e1f6618"
   
   strings:
   	  
   	  $drp = "loaddll32.exe" fullword wide
      
      // IP will change, current for 4b2a101f9e7e0119409b6faae798c1e9fada080f055509f477c598365e1f6618 only
      $ip1 = "77.220.64.131:443" ascii
      $ip2 = "5.196.204.251:5037" ascii
      $ip3 = "192.99.41.136:981", ascii
      $ip4 = "24.229.3.146:4664" ascii
      
      $s2 = "c:\\CoolFamily\\NounWhat\\MostKill\\ReadyCity\\lost.pdb" fullword ascii
      $s3 = "lost.dll" fullword ascii
      $s5 = "<command:command xmlns:maml=\"http://schemas.microsoft.com/maml/2004/10\" xmlns:command=\"http://schemas.microsoft.com/maml/dev/" ascii
      $s6 = "<!-- v 1.1.0.9 -->" fullword ascii
      $s7 = " &quot;get-eventlog -list&quot;." fullword ascii
      $s17 = " &quot;get-psdrive | format name, description&quot;. " fullword ascii
      

   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 3 of them or 2 of ($ip*) or ($drp and 2 of them) 
}
