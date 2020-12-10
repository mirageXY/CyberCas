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
    class MiniDump
    {
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
            ref MINIDUMP_EXCEPTION_INFORMATION expParam,
            IntPtr userStreamParam,
            IntPtr callbackParam);
        private struct MINIDUMP_EXCEPTION_INFORMATION

        {
            public uint ThreadId;
            public IntPtr ExceptionPointers;
            public int ClientPointers;
        }
        private enum MINIDUMP_TYPE
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

        public void Dump_Process()
        {
            MINIDUMP_TYPE DumpLevel = MINIDUMP_TYPE.MiniDumpIgnoreInaccessibleMemory;

            string assemblyPath = Assembly.GetEntryAssembly().Location;
            string dumpFileName = assemblyPath + "_" + DateTime.Now.ToString("dd.MM.yyyy.HH.mm.ss") + ".dmp";
            FileStream file = new FileStream(dumpFileName, FileMode.Create);

            MINIDUMP_EXCEPTION_INFORMATION info = new MINIDUMP_EXCEPTION_INFORMATION();
            info.ClientPointers = 0;
            info.ExceptionPointers = Marshal.GetExceptionPointers();
            info.ThreadId = kernel32.GetCurrentThreadId();

            // Get the current process.
            Process targetProcess = null;
            Process[] proc_lsass = Process.GetProcessesByName("lsass");
            targetProcess = proc_lsass[0];

            //GetCurrentProcess()
            // A full memory dump is necessary in the case of a managed application, other wise no information
            // regarding the managed code will be available
            bool state = MiniDumpWriteDump(targetProcess.Handle, kernel32.GetCurrentProcessId(),
                file.SafeFileHandle, DumpLevel, ref info, IntPtr.Zero, IntPtr.Zero);
            // the first last error check is fine here:
            Console.WriteLine(Marshal.GetLastWin32Error());
            Console.WriteLine(kernel32.GetLastError());

            file.Close();
            string exeName = Path.GetFileName(assemblyPath);
            Console.WriteLine(" state = ");
            Console.WriteLine(state.ToString());

            Console.WriteLine
            (String.Format("Creating Dump For Process: {0} ({1}) to {2}", targetProcess.ProcessName, targetProcess.Id, dumpFileName));
        }
    }
}
