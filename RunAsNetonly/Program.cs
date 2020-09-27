using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace RunAsNetonly
{
    [StructLayout(LayoutKind.Sequential)]
    public class SECURITY_ATTRIBUTES

    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
        public SECURITY_ATTRIBUTES()
        {
            nLength = 12;
            lpSecurityDescriptor = IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct StartupInfo
    {
        public int cb;
        public String reserved;
        public String desktop;
        public String title;
        public int x;
        public int y;
        public int xSize;
        public int ySize;
        public int xCountChars;
        public int yCountChars;
        public int fillAttribute;
        public int flags;
        public UInt16 showWindow;
        public UInt16 reserved2;
        public byte reserved3;
        public SafeFileHandle stdInput;
        public SafeFileHandle stdOutput;
        public SafeFileHandle stdError;
    }

    public struct ProcessInformation
    {
        public IntPtr process;
        public IntPtr thread;
        public int processId;
        public int threadId;
    }

    [Flags]
    public enum CreationFlags
    {
        CREATE_SUSPENDED = 0x4,
        CREATE_NEW_CONSOLE = 0x10,
        CREATE_NEW_PROCESS_GROUP = 0x200,
        CREATE_UNICODE_ENVIRONMENT = 0x400,
        CREATE_SEPARATE_WOW_VDM = 0x800,
        CREATE_DEFAULT_ERROR_MODE = 0x4000000
    }

    [Flags]
    public enum LogonFlags
    {
        LOGON_WITH_PROFILE = 0x1,
        LOGON_NETCREDENTIALS_ONLY = 0x2
    }

    [Flags]
    public enum WaitFlags
    {
            WAIT_ABANDONED = 0x00000080,
            WAIT_OBJECT_0 = 0x00000000,
            WAIT_TIMEOUT = 0x00000102
    }

    internal class MonitorObject
    {
        public StreamReader s;
        public CancellationToken c;
    }

    class Program
    {

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        const int STARTF_USESTDHANDLES = 0x100;

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]

        public static extern bool CreatePipe(
            out SafeFileHandle hReadPipe,
            out SafeFileHandle hWritePipe,
            SECURITY_ATTRIBUTES lpPipeAttributes,
            int nSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]

        public static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            SafeHandle hSourceHandle,
            IntPtr hTargetProcess,
            out SafeFileHandle targetHandle,
            int dwDesiredAccess,
            bool bInheritHandle,
            int dwOptions);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]

        public static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]

        public static extern bool CreateProcessWithLogonW(
            String userName,
            String domain,
            String password,
            LogonFlags logonFlags,
            String applicationName,
            String commandLine,
            CreationFlags creationFlags,
            UInt32 environment,
            String currentDirectory,
            ref StartupInfo startupInfo,
            ref ProcessInformation processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        public static void Main(string[] args)
        {
            if (args.Length != 4)
            {
                Console.WriteLine("usage: runnetonly.exe <username> <password> <domain> <command>");
            }
            else
            {
                String userName = args[0];
                String password = args[1];
                String domain = args[2]; /// "." for no domain / local computer
                String command = args[3]; ///  "cmd.exe" or "c:\windows\system32\cmd.exe /c echo test"
                LaunchNewProcess(userName, password, domain, command);
            }
        }


        public static void LaunchNewProcess(string userName, string password, string domain, string command)
        {
            SafeFileHandle hChildStd_In_Rd = null;
            SafeFileHandle hChildStd_In_Wr = null;
            SafeFileHandle hChildStd_Out_Rd = null;
            SafeFileHandle hChildStd_Out_Wr = null;

            CreatePipe(out hChildStd_In_Wr, out hChildStd_In_Rd, true);
            CreatePipe(out hChildStd_Out_Wr, out hChildStd_Out_Rd, true);

            StartupInfo startupInfo = new StartupInfo();
            startupInfo.cb = Marshal.SizeOf(startupInfo);
            startupInfo.flags = STARTF_USESTDHANDLES;

            startupInfo.stdInput = hChildStd_In_Rd;
            startupInfo.stdOutput = hChildStd_Out_Wr;
            startupInfo.stdError = hChildStd_Out_Wr;

            int bufferSize = 0x1000;

            StreamWriter stdInput = new StreamWriter(
                new FileStream(hChildStd_In_Wr, FileAccess.Write, bufferSize, false),
                Console.InputEncoding,
                bufferSize);
            stdInput.AutoFlush = true;

            StreamReader stdOutput = new StreamReader(
                new FileStream(hChildStd_Out_Rd, FileAccess.Read, bufferSize, false),
                Console.OutputEncoding,
                true,
                bufferSize);

            StreamReader error = new StreamReader(
                new FileStream(hChildStd_Out_Rd, FileAccess.Read, bufferSize, false),
                Console.OutputEncoding,
                true,
                bufferSize);

            CancellationTokenSource cts = new CancellationTokenSource();

            Thread t1 = new Thread(new ParameterizedThreadStart(MonitorOutputOfChildProcess));
            MonitorObject mon1 = new MonitorObject();
            mon1.s = error;
            mon1.c = cts.Token;
            t1.Start(mon1);

            Thread t2 = new Thread(new ParameterizedThreadStart(MonitorOutputOfChildProcess));

            MonitorObject mon2 = new MonitorObject();
            mon2.s = stdOutput;
            mon2.c = cts.Token;

            t2.Start(mon2);

            ProcessInformation processInfo = new ProcessInformation();
            String currentDirectory = System.IO.Directory.GetCurrentDirectory();

            Console.WriteLine("starting process");
            CreateProcessWithLogonW(userName, domain, password,
                LogonFlags.LOGON_NETCREDENTIALS_ONLY,
                null,
                command,
                (UInt32)0,
                (UInt32)0,
                currentDirectory,
                ref startupInfo,
                ref processInfo);

 
            Boolean running = true;

            while (running) {
                if (Console.KeyAvailable)
                {
                    String input = Console.ReadLine();
                    stdInput.WriteLine(input);
                }
                if (WaitForSingleObject(processInfo.process, 10) == (uint)WaitFlags.WAIT_OBJECT_0)
                {
                    running = false;
                }
            }
            cts.Cancel();
            Console.WriteLine("end");
        }

        private static async void MonitorOutputOfChildProcess(object state)
        {
            MonitorObject mon = state as MonitorObject;

            StreamReader stdOutput = mon.s;
            CancellationToken ct = mon.c;
            while(!ct.IsCancellationRequested) 
            {
                int bufferSize = 10240;
                char[] buffer = new char[bufferSize];
                int count = await stdOutput.ReadAsync(buffer, 0, bufferSize);
                string line = new string(buffer, 0, count);
                if (line.Length > 0)
                {
                    Console.Write(line);
                }
                Thread.Sleep(10);
            }
        }

        private static async void MonitorOutputOfChildProcessErr(object state)
        {
            TextWriter errorWriter = Console.Error;
            MonitorObject mon = state as MonitorObject;

            StreamReader stdError = mon.s;
            CancellationToken ct = mon.c;
            while (!ct.IsCancellationRequested)
            {
                int bufferSize = 10240;
                char[] buffer = new char[bufferSize];
                int count = await stdError.ReadAsync(buffer, 0, bufferSize);
                string line = new string(buffer, 0, count);
                if (line.Length > 0)
                {
                    errorWriter.Write(line);
                }
                Thread.Sleep(10);
            }
        }

        private static void CreatePipe(out SafeFileHandle parentHandle, out SafeFileHandle childHandle, bool parentInputs)
        {
            SECURITY_ATTRIBUTES lpPipeAttributes = new SECURITY_ATTRIBUTES();
            lpPipeAttributes.bInheritHandle = true;
            SafeFileHandle hWritePipe = null;
            try
            {
                if (parentInputs)
                {
                    CreatePipeWithSecurityAttributes(out childHandle, out hWritePipe, lpPipeAttributes, 0);
                }
                else
                {
                    CreatePipeWithSecurityAttributes(out hWritePipe, out childHandle, lpPipeAttributes, 0);
                }
                if (!DuplicateHandle(GetCurrentProcess(), hWritePipe, GetCurrentProcess(), out parentHandle, 0, false, 2))
                {
                    throw new Win32Exception();
                }
            }
            finally
            {
                if ((hWritePipe != null) && !hWritePipe.IsInvalid)
                {
                    hWritePipe.Close();
                }
            }
        }

        private static void CreatePipeWithSecurityAttributes(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe, SECURITY_ATTRIBUTES lpPipeAttributes, int nSize)
        {
            if ((!CreatePipe(out hReadPipe, out hWritePipe, lpPipeAttributes, nSize) || hReadPipe.IsInvalid) || hWritePipe.IsInvalid)
            {
                throw new Win32Exception();
            }
        }

    }
}





