
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using System.Collections;
using System.Reflection.Metadata.Ecma335;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Tracing.Parsers.LinuxKernel;
using Microsoft.Diagnostics.Tracing.Parsers.Clr;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Utilities;
using Microsoft.Diagnostics.Tracing.StackSources;
using Microsoft.Diagnostics.Tracing.Analysis;
using Microsoft.Diagnostics.Symbols;
using System.Numerics;

// i lowkey forgot why i put that name but nigerald ballin !!
class anime_catgirl
{
    static object l_stdout = 0; // a stupid lock
    static byte big_addr = 0;
    static EventLog eventLog;

#if DEBUG
    [DllImport("C:\\Users\\test\\source\\repos\\domchell_based_monogatari\\x64\\Debug\\hsb.dll")]
#else
    [DllImport("hsb.dll")]
#endif
    static extern uint IsUnbacked( ulong StartAddress, uint dwPid);

    static Dictionary<int, string> Processes = new Dictionary<int, string>();
    static void Main()
    {
        if (!EventLog.SourceExists("bruhlog"))
        {
            EventLog.CreateEventSource("Image Load", "bruhlog");
            EventLog.CreateEventSource("Process Start", "bruhlog");
            EventLog.CreateEventSource("Thread Start", "bruhlog");
        }

        eventLog = new EventLog("bruhlog");

        foreach (ProcessModule mod in Process.GetCurrentProcess().Modules)
        {
            if (mod.FileName.Contains("ntdll.dll"))
            {
                big_addr = (byte)((ulong)mod.BaseAddress >> 40);
                break;
            }
        }
        
        using ( TraceEventSession KernelTraceSession = new TraceEventSession( "NT Kernel Session" ) )
        {
            Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e) { KernelTraceSession.Dispose(); };
            KernelTraceSession.EnableKernelProvider(
                KernelTraceEventParser.Keywords.ImageLoad |
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.Thread,

                // Stack capture for these events
                KernelTraceEventParser.Keywords.ImageLoad |
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.Thread
                );

            using ( var KernelTrace = Microsoft.Diagnostics.Tracing.Etlx.TraceLog.CreateFromTraceEventSession(KernelTraceSession)) 
            {
                KernelTrace.Kernel.ImageLoad += ImageLoadEvent;
                KernelTrace.Kernel.ProcessStart += ProcessStartEvent;
                KernelTrace.Kernel.ProcessStop += ProcessStopEvent;
                KernelTrace.Kernel.ThreadStart += ThreadStartEvent;
                KernelTrace.Process();

            }
        }
    }

    /*
        ImageLoadEvent
        ImageBase: 140724140572672
        ImageSize: 368640
        ImageChecksum: 362169
        TimeDateStamp: -786423885
        DefaultBase: 140724140572672
        BuildTime: 3/6/2081 7:23:31 PM
        FileName: C:\Windows\System32\ncryptprov.dll
    */
    static void ImageLoadEvent(ImageLoadTraceData data)
    {
        IndexProc(data.ProcessID, data.ProcessName);
        var cs = data.CallStack();
        string Alert = "#####################################################\n";
        string s_cs = $"PID: {data.ProcessID}\n";
        if (cs != null)
        {
            int i = cs.Depth;
            while (cs != null)
            {
                TraceCodeAddress codeAddress = cs.CodeAddress;
                TraceModuleFile moduleFile = codeAddress.ModuleFile;

                if (IsUnbacked(codeAddress.Address, (uint)data.ProcessID) > 0 && codeAddress.Address > 0)
                {
                    if ((codeAddress.Address >> 40) != big_addr && !codeAddress.ModuleFilePath.ToLower().Contains("microsoft.net")) // uhhh we ignore this LAWLS
                    {
                        s_cs += $"{i}| 0x{codeAddress.Address:X}: BAD\n";
                        break;
                    }
                }
                s_cs += $"{i}| 0x{codeAddress.Address:X}: {codeAddress.ModuleFilePath}\n";
                i--;
                cs = cs.Caller;
            }

            if (i != 0)
            {
                Alert += $"UNBACKED IMAGE LOAD DETECTED!\n" +
                    $"Timestamp: {data.TimeStamp}\n" +
                    $"Process: {data.ProcessName}\n" +
                    s_cs;
                lock (l_stdout)
                {
                    Console.WriteLine(Alert);
                }
                Log("Image Load", Alert, 1);
            }
        }
        
    }
    /*
    ProcessStartEvent
    ProcessID: 6120
    ParentID: 3532
    ImageFileName: notepad.exe
    PageDirectoryBase: 3037528064
    Flags: None
    SessionID: 1
    ExitStatus: 0
    UniqueProcessKey: 18446641331088289920
    CommandLine: "C:\Windows\system32\notepad.exe"
    PackageFullName:
    ApplicationID:
    */
    static void ProcessStartEvent( ProcessTraceData data )
    {
        string Command = (string)data.PayloadByName("ImageFileName");
        string Alert = "################################################\n";
        
        IndexProc(data.ProcessID, data.ProcessName);
        IndexProc(data.ParentID, "");
        string Parent = Processes.FirstOrDefault(proc => proc.Key == data.ParentID).Value;
        lock ( l_stdout )
        {
            switch ( Command )
            {
                case "cmd.exe":
                    Alert += "cmd.exe was run!\n";
                    break;
                case "powershell.exe":
                    Alert += "powershell.exe was run!\n";
                    break;
                case "sc.exe":
                    Alert += "sc.exe was run!\n";
                    break;
                case "netsh.exe":
                    Alert += "netsh.exe was run!\n";
                    break;
                case "whoami.exe":
                    Alert += "whoami.exe was run!\n";
                    break;
                case "net.exe":
                    Alert += "net.exe was run!\n";
                    break;
                case "net1.exe":
                    Alert += "net1.exe was run!\n";
                    break;
                default:
                    return;
            }
            Alert += $"Timestamp: {data.TimeStamp}\n";
            Alert += $"PID: {data.ProcessID}\n";
            Alert += $"PPID: {data.ParentID}\n";
            if (!String.IsNullOrEmpty(Parent))
            {
                Alert += $"Parent Name: {Parent}\n";
            }
            Alert += $"Full Command: {(string)data.PayloadByName("CommandLine")}\n";
            Console.WriteLine(Alert);
            Log("Process Start", Alert, 2);
        }
    }

    static void ProcessStopEvent(ProcessTraceData data)
    {
        lock (Processes)
        {
            if (Processes.Any(entry => entry.Key == data.ProcessID))
            {
                Processes.Remove(data.ProcessID);
            }
        }
    }

    /*
        Thread Start Event
        StackBase: 18446740251268059136
        StackLimit: 18446740251268034560
        UserStackBase: 35950952448
        UserStackLimit: 35950919680
        StartAddr: 15
        Win32StartAddr: 140706409360176
        TebBase: 35949277184
        SubProcessTag: 0
        BasePriority: 8
        PagePriority: 5
        IoPriority: 2
        ThreadFlags: 0
        ThreadName:
        ParentThreadID: 36
        ParentProcessID: 4
    */
    static void ThreadStartEvent( ThreadTraceData data )
    {
        uint code = IsUnbacked((ulong)data.PayloadByName("Win32StartAddr"), (uint)data.ProcessID);
        string Alert = "#####################################################\n";
        if ( code > 0 )
        {
           
            IndexProc(data.ProcessID, data.ProcessName);
            IndexProc(data.ParentProcessID, "");

            lock (l_stdout)
            {
                switch (code)
                {
                    case 1:
                        Alert += $"Detected thread starting at unbacked address!\n";
                        break;
                    case 2:
                        Alert += $"Detected thread starting at stomped address!\n";
                        break;
                    case 3:
                        Alert += $"Detected thread starting at freed address!\n";
                        break;
                }
                Alert += $"Timestamp: {data.TimeStamp}\n" +
                        $"PPID: {data.ParentProcessID}\n" +
                        $"PID: {data.ProcessID}\n" +
                        $"TID: {data.ThreadID}\n" +
                        $"Process: {Processes.FirstOrDefault(proc => proc.Key == data.ProcessID).Value}\n" +
                        $"Thread Creator: {Processes.FirstOrDefault(proc => proc.Key == data.ParentProcessID).Value}\n";
                Console.WriteLine(Alert);
            }
            Log("Thread Start", Alert, 3);
        }
        //if (data.ProcessID == 5356) 
        //{
        //    DbgPrint("============Thread Start Event============");
        //    foreach (string s in data.PayloadNames)
        //    {
        //        DbgPrint($"{s}: {data.PayloadByName(s)}");
        //    }
        //}
    }

    static void IndexProc(int pid, string n_proc) // n_proc is optional
    {
        string ProcessName = "";
        if (n_proc.Length > 0)
        {
            ProcessName = n_proc;
        }

        if (Processes.Any(proc => proc.Key == pid && proc.Value.Length == 0))
        {
            lock (Processes)
            {
                if (ProcessName.Length == 0)
                {
                    try
                    {
                        ProcessName = Process.GetProcessById(pid).ProcessName;
                    }
                    catch
                    {
                    }
                }
                Processes[pid] = ProcessName;
                
            }
        }
        else if (!Processes.Any(entry => entry.Key == pid))
        {
            lock (Processes)
            {
                if (ProcessName.Length == 0)
                {
                    try
                    {
                        ProcessName = Process.GetProcessById(pid).ProcessName;
                    }
                    catch
                    {
                    }
                }
                Processes.Add(pid, ProcessName);
            }
        }
    }
    static void DbgPrint(string str)
    {
#if DEBUG
        lock (l_stdout)
        {
            Console.WriteLine(str);
        }
#endif
    }
    static void Log(string evtName, string evt, int id)
    {
        if (eventLog != null)
        {
            lock (eventLog)
            {
                eventLog.Source = evtName;
                eventLog.WriteEntry(evt, EventLogEntryType.Information, id, 0, new byte[] { });
            }
        }
    }
}