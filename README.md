# CyberCas
 
#MiniDump Objectives:

Dump lsass process to dmp file at the same exe directory
Get system privillege to the same executing process. Currently process explorer sees it as Admin, but WindowsIdentity.GetCurrent().IsSystem returns True. However, Launching another process with system privillege is successfull as task manager, process explorer, and WindowsIdentity see the new process as system.
Checks of AV is installed on the system.
#SharpDPAPI Compiled from this repo: https://github.com/GhostPack/SharpDPAPI

Few changes were made to compile on VS2015 .NET 4.0
