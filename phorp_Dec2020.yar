rule phorp_New_2021_B
{
	meta: 
		description = "Detecting recent phorpiex variant"
		author = "@is_henderson"
		date = "15 December 2021"
		sha256 = "7c419f22e51f37be0c483bbf3c320c40b6939785896b756c504af5de5b46237f"
	strings:		
		$a1 = "ShEllExECutE=__\\DriveMgr.exe" fullword wide
		$a2 = "/c start __ & __\\DriveMgr.exe & exit" fullword wide
		$a3 = "qpx7g2fyuwq48npc3mscuzr04z6knnkj0swcy4e0xj" fullword ascii
		$c1 = {68 74 74 70 3A 2F 2F 77 77 77 2E 79}
		$c2 = {3A 2F 2F 31 38 35 2E 32}
		$c3 = {31 30 38 32 38 30 31 38 39 35 34 39 35 39 35 30} // Bitcoin Cash Address
	condition:
		uint16(0) == 0x5A4D and filesize < 1MB and 3 of them

}
