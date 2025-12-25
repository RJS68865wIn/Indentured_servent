' Creates a desktop shortcut for Indentured Servant
Set oWS = WScript.CreateObject("WScript.Shell")
userDesktop = oWS.SpecialFolders("Desktop")

Set oLink = oWS.CreateShortcut(userDesktop & "\Indentured Servant.lnk")
oLink.TargetPath = "indentured_servant.exe"
oLink.WorkingDirectory = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
oLink.Description = "Indentured Servant - Cybersecurity Assistant"
oLink.Save
