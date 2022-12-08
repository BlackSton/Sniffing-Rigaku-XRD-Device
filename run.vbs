Set WshShell = CreateObject("WScript.Shell")
WshShell.Run chr(34) & "C:\Users\Administrator\Desktop\Test\sniff\main.bat" & Chr(34), 0
Set WshShell = Nothing