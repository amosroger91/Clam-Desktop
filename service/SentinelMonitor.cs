using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceProcess;

// A small SCM host. The job object ensures the agent AND clamd exit when this host stops or crashes.
public sealed class SentinelMonitor : ServiceBase {
    Process child;
    IntPtr job;
    readonly string runtime, agent, profile;
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern IntPtr CreateJobObject(IntPtr attrs, string name);
    [DllImport("kernel32.dll")] static extern bool SetInformationJobObject(IntPtr job, int type, IntPtr info, uint length);
    [DllImport("kernel32.dll")] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [StructLayout(LayoutKind.Sequential)] struct Basic {
        public long PerProcess, PerJob;
        public uint Flags;
        public UIntPtr MinWorkingSet, MaxWorkingSet;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)] struct Io { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] struct Extended {
        public Basic Basic;
        public Io Io;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    static string Quote(string text) {
        if (text.IndexOf('"') >= 0 || text.EndsWith("\\")) throw new ArgumentException("Invalid argument path");
        return "\"" + text + "\"";
    }
    SentinelMonitor(string runtime, string agent, string profile) {
        this.runtime = Path.GetFullPath(runtime); this.agent = Path.GetFullPath(agent); this.profile = Path.GetFullPath(profile);
        ServiceName = "SentinelMonitor"; CanStop = true; CanShutdown = true;
    }
    protected override void OnStart(string[] args) {
        job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new Exception("Could not create scanner process job");
        var info = new Extended(); info.Basic.Flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        IntPtr memory = Marshal.AllocHGlobal(Marshal.SizeOf(info));
        try {
            Marshal.StructureToPtr(info, memory, false);
            if (!SetInformationJobObject(job, 9, memory, (uint)Marshal.SizeOf(info))) throw new Exception("Could not configure scanner process job");
        } finally { Marshal.FreeHGlobal(memory); }
        var start = new ProcessStartInfo(runtime, Quote(agent) + " " + Quote(profile));
        start.UseShellExecute = false; start.CreateNoWindow = true; start.WorkingDirectory = Path.GetDirectoryName(agent);
        start.EnvironmentVariables["ELECTRON_RUN_AS_NODE"] = "1";
        start.EnvironmentVariables["SENTINEL_SERVICE"] = Environment.UserInteractive ? "0" : "1";
        // The child waits for this file, so it cannot create clamd before joining the kill-on-close job.
        string gate = Path.Combine(profile, "monitor", "host-" + Guid.NewGuid().ToString("N"));
        start.EnvironmentVariables["SENTINEL_HOST_GATE"] = gate;
        child = Process.Start(start);
        if (!AssignProcessToJobObject(job, child.Handle)) { child.Kill(); throw new Exception("Could not attach scanner to process job"); }
        File.WriteAllText(gate, "ready");
        child.EnableRaisingEvents = true;
        child.Exited += delegate { Environment.Exit(child.ExitCode == 0 ? 0 : 1); };
    }
    protected override void OnStop() { if (job != IntPtr.Zero) { CloseHandle(job); job = IntPtr.Zero; } }
    protected override void OnShutdown() { OnStop(); }
    public static void Main(string[] args) {
        if (args.Length < 3) throw new ArgumentException("runtime, agent, and profile paths are required");
        var host = new SentinelMonitor(args[0], args[1], args[2]);
        if (args.Length > 3 && args[3] == "--console") {
            host.OnStart(new string[0]);
            Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs e) { host.OnStop(); };
            AppDomain.CurrentDomain.ProcessExit += delegate { host.OnStop(); };
            host.child.WaitForExit(); host.OnStop();
        } else ServiceBase.Run(host);
    }
}
