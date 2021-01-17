rule phorp_New_2021

{
	meta: 
		description = "Detecting recent phorpiex variant"
		author = "@is_henderson"
		date = "15 December 2021"
		sha256 = "7c419f22e51f37be0c483bbf3c320c40b6939785896b756c504af5de5b46237f"
	
	strings:		
		/*
		$s1 = "3hr93hr93r9g3grg39rg3g9r93gr9g3gr93rg93gr9g3gr93rg939rg39gr9g393hr93hr93r9g3grg39rg3g9r93gr9g3gr93rg93gr9g3gr93rg939rg39gr9g393h" wide
        $s2 = "36er63e63ed3ed63ded63d6ed36de636d3ed6ed63ed6e3d6e3d63ed6e3d36er63e63ed3ed63ded63d6ed36de636d3ed6ed63ed6e3d6e3d63ed6e3d36er63e63e" wide
        $s3 = "7wf7wf77f7wf7w7f7wf7wf77f7wf7w7f7wf7wf77f7wf7w7f7wf7wf77f7wf7w7f7wf7wf77f7wf7w7f7wf7wf77f7wf7w7f7wf7wf77f7wf7w7f7wf7wf77f7wf7w7f" wide
        $s4 = "lpflpk3ofk3pkfpkpk3fpfpf3pkpk3fpflpflpk3ofk3pkfpkpk3fpfpf3pkpk3fpflpflpk3ofk3pkfpkpk3fpfpf3pkpk3fpflpflpk3ofk3pkfpkpk3fpfpf3pkpk" wide
        $s5 = "fnf4nf94nf4949f9f4f4nfnf4nf94nf4949f9f4f4nfnf4nf94nf4949f9f4f4nfnf4nf94nf4949f9f4f4nfnf4nf94nf4949f9f4f4nfnf4nf94nf4949f9f4f4nfn" wide
        $s6 = "4ofkwo4fkw4okwfok4kf4ofkwo4fkw4okwfok4kf4ofkwo4fkw4okwfok4kf4ofkwo4fkw4okwfok4kf4ofkwo4fkw4okwfok4kf4ofkwo4fkw4okwfok4kf4ofkwo4f" wide
        */        
		
		$a1 = "ShEllExECutE=__\\DriveMgr.exe" fullword wide
		$a2 = "/c start __ & __\\DriveMgr.exe & exit" fullword wide
		$a3 = "qpx7g2fyuwq48npc3mscuzr04z6knnkj0swcy4e0xj" fullword ascii
		
		/*
		// $b are c2's pulled from sample and will change
		$b1 = "http://tsrv4.ws/" fullword ascii // c2
		$b2 = "http://tldrbox.top/" fullword ascii //c2
		$b3 = "http://185.215.113.10/" fullword ascii
		$b4 = "http://tsrv3.ru/" fullword ascii
		$b5 = "http://zzruuoooshfrohu.su/" fullword ascii		
		*/
		
		$c1 = {68 74 74 70 3A 2F 2F 77 77 77 2E 79}
		$c2 = {3A 2F 2F 31 38 35 2E 32}
		$c3 = {31 30 38 32 38 30 31 38 39 35 34 39 35 39 35 30} // Bitcoin Cash Address
        
	condition:
		uint16(0) == 0x5A4D and filesize < 1MB and 3 of them
		// uint16(0) == 0x5A4D and any of ($a*) or 2 of ($b*,$c*) or 2 of (s*) and filesize < 1MB 
}
