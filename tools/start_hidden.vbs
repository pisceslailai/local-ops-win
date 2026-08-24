Option Explicit

' Explorer shortcuts keep a cmd.exe window on the taskbar while start.bat
' waits for the long-running console. Launch it through WScript instead.
Dim shell, files, root, command
Set shell = CreateObject("WScript.Shell")
Set files = CreateObject("Scripting.FileSystemObject")
root = files.GetParentFolderName(WScript.ScriptFullName)
root = files.GetParentFolderName(root)
command = Quote(shell.ExpandEnvironmentStrings("%ComSpec%")) _
    & " /d /c call " & Quote(files.BuildPath(root, "start.bat"))
shell.Run command, 0, False

Function Quote(value)
    Quote = Chr(34) & value & Chr(34)
End Function
