rule Jbox_Dridex_1_Feb_2021 
{   
   meta:      
      description = "Dridex - Updated"
      author = "Ian Harte - @is_henderson"
      reference = "https://www.joesandbox.com/analysis/346906/0/html"
      date = "2021-02-01"
      hash1 = "4b2a101f9e7e0119409b6faae798c1e9fada080f055509f477c598365e1f6618"
   
   strings:   	  
   	
      
      // IP will change, current for 4b2a101f9e7e0119409b6faae798c1e9fada080f055509f477c598365e1f6618 only
      $ip1 = "77.220.64.131" wide // :443
      $ip2 = "5.196.204.251" wide // :5037
      $ip3 = "192.99.41.136" wide // :981
      $ip4 = "24.229.3.146" wide // :4664
      
      $s1 = "c:\\CoolFamily\\NounWhat\\MostKill\\ReadyCity\\lost.pdb" ascii wide
      $s2 = "lost.dll" ascii wide
      $s3 = "<command:command xmlns:maml=\"http://schemas.microsoft.com/maml/2??4/10\" xmlns:command=\"http://schemas.microsoft.com/maml/dev/" wide
      $s4 = "<!-- v 1.1.0.9 -->" ascii wide
      $s5 = " &quot;get-eventlog -list&quot;." ascii wide
      $s6 = " &quot;get-psdrive | format name, description&quot;. " ascii wide
      $s7 = "loaddll32.exe" ascii wide

      $op0 = { e8 83 f0 ?? ?? 59 59 8b 75 08 8d 34 f5 70 f0 47 }
      $op1 = { 3b c3 74 17 39 18 75 13 50 e8 8e ed ?? ?? ?? b6 }
      $op2 = { 56 ?? b4 24 34 06 ?? ?? 8d 4c 24 48 e8 ba 5a 01 }
      $op3 = { 68 b5 77 e8 34 68 39 67 4e fa e8 db d4 ?? ?? 8b }
      $op4 = { e8 3d c7 01 ?? 8d 4c 24 78 e8 34 c7 01 ?? 8d 4c }       
      $op5 = { 75 6e 57 68 61 74 5c 4d 6f 73 74 4b 69 6c 6c 5c } //unWhat\MostKill\
      $op6 = { 52 65 61 64 79 43 69 74 79 5c 6c 6f 73 74 2e 70 } // ReadyCity\lost.p
      $op7 = { 6c 6f 73 74 2e 64 6c 6c ?? 53 68 6f 70 73 65 6c } // lost.dll.Shopsel   
      
   condition:  
      uint16(0) == 0x5a4d and filesize < 2000KB and 3 of them
}
