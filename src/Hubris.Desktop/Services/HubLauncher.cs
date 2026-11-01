using System.Diagnostics;

namespace Hubris.Desktop.Services;

/// <summary>Starts a local test instance of the hub with stdin held open, so it shows up in the dashboard.</summary>
public sealed class HubLauncher : IDisposable
{
    private readonly List<Process> _owned = new();
    private readonly object _gate = new();

    public event Action<string>? Output;

    /// <summary>Best-effort location of the server binary: next to this executable, then the sibling publish dir.</summary>
    public static string? FindServerExecutable()
    {
        string exeName = OperatingSystem.IsWindows() ? "Hubris.exe" : "Hubris";
        string baseDir = AppContext.BaseDirectory;
        string[] candidates =
        [
            Path.Combine(baseDir, exeName),
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "Hubris", "bin", "Release", "net10.0", RidFolder(), "publish", exeName)),
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "..", "Hubris", "bin", "Release", "net10.0", RidFolder(), "publish", exeName)),
        ];
        foreach (var c in candidates)
            if (File.Exists(c)) return c;
        return null;
    }

    private static string RidFolder()
    {
        string os = OperatingSystem.IsWindows() ? "win" : OperatingSystem.IsMacOS() ? "osx" : "linux";
        string arch = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture switch
        {
            System.Runtime.InteropServices.Architecture.Arm64 => "arm64",
            System.Runtime.InteropServices.Architecture.X86 => "x86",
            _ => "x64",
        };
        return $"{os}-{arch}";
    }

    public int Launch(string exe, IReadOnlyList<string> args, string? workingDirectory)
    {
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        if (!string.IsNullOrEmpty(workingDirectory) && Directory.Exists(workingDirectory)) psi.WorkingDirectory = workingDirectory;

        var p = new Process { StartInfo = psi, EnableRaisingEvents = true };
        p.OutputDataReceived += (_, e) => { if (e.Data is not null) Output?.Invoke($"[{p.Id} stdout] {e.Data}"); };
        p.ErrorDataReceived += (_, e) => { if (e.Data is not null) Output?.Invoke($"[{p.Id}] {e.Data}"); };
        p.Exited += (_, _) =>
        {
            Output?.Invoke($"[{p.Id}] exited with code {p.ExitCode}");
            lock (_gate) _owned.Remove(p);
        };
        p.Start();
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();

        // Drive the MCP handshake so the hub reports a client name and leaves stdin open.
        p.StandardInput.AutoFlush = true;
        p.StandardInput.Write("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"Hubris Desktop (test instance)\",\"version\":\"1.0.0\"}}}\n");
        p.StandardInput.Write("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n");

        lock (_gate) _owned.Add(p);
        return p.Id;
    }

    public bool Stop(int pid)
    {
        Process? p;
        lock (_gate) p = _owned.Find(x => x.Id == pid);
        if (p is null) return false;
        try { p.StandardInput.Close(); } catch (Exception) { }
        return true;
    }

    public void Dispose()
    {
        Process[] all;
        lock (_gate) { all = _owned.ToArray(); _owned.Clear(); }
        foreach (var p in all)
        {
            try { p.StandardInput.Close(); } catch (Exception) { }
            try { if (!p.WaitForExit(1500)) p.Kill(entireProcessTree: true); } catch (Exception) { }
            p.Dispose();
        }
    }
}
