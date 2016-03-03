'
'	InjectScript.dll example For Basic Process Manipulation Tool Kit (BPMTK)
'	Source code put in public domain by Didier Stevens, no Copyright
'	https://DidierStevens.com
'	Use at your own risk
'
'	History:
'	2009/06/09: Start development
'

MsgBox "Starting Search and Replace"
FindMemoryPages &h00080000, &h00A00000, MakeSearchArray("F", "indThisString"), "HackThisString"
MsgBox "Done"

Function MakeSearchArray(str1, str2)
	Dim result()
	
	ReDim result(Len(str1) + Len(str2)-1)
	For i = 1 to Len(str1)
		result(i-1) = Asc(Mid(str1, i, 1))
	Next
	For i = 1 to Len(str2)
		result(i-1+Len(str1)) = Asc(Mid(str2, i, 1))
	Next
	
	MakeSearchArray = result
End Function

Sub FindMemoryPages(argStart, argEnd, aSearch, strReplace)
	start = 0
	address = argStart
	While address < argEnd
		If scriptengine.Peek(address) = -1 Then
			If start <> 0 Then
				scriptengine.Output("Page address: " & Hex8(start) & " size: " & Hex8(address - start))
				If SearchAndReplaceUnicode(start, address - start, aSearch, strReplace) = 1 Then
					Exit Sub
				End If
				start = 0
			End If
		Else
			If start = 0 Then
				start = address
			End If
		End If
		address = address + &h00001000
	Wend
End Sub

'len of aSearch and strReplace must be the same
Function SearchAndReplaceUnicode(memStart, memSize, aSearch, strReplace)
	searchSize = UBound(aSearch)
	result = 0
	
	For i = memStart To memStart + memSize - 1 Step 2
		found = 1
		For j = 0 to searchSize
			If scriptengine.Peek(i+j*2) <> aSearch(j) Or scriptengine.Peek(i+j*2+1) <> 0 Then
				found = 0
				Exit For
			End If
		Next
		If found = 1 Then
			scriptengine.Output("Found string: " & Hex8(i))
			For j = 0 to searchSize
				scriptengine.Poke i+j*2, Asc(Mid(strReplace, j+1, 1))
			Next
			result = 1
		End If
	Next
	
	SearchAndReplaceUnicode = result
End Function

Function Hex8(value)
	result = Hex(value)
	While Len(result) < 8
		result = "0" + result
	Wend
	Hex8 = result
End Function
