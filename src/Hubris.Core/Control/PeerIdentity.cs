using System.Runtime.InteropServices;
using System.Net.Sockets;
using Hubris.Transport;

namespace Hubris.Control;

/// <summary>Who is on the other end of a Unix socket: the peer's pid and executable, from the kernel, not from the client.</summary>
public static partial class PeerIdentity
{
    [LibraryImport("libc", SetLastError = true)]
    private static partial int getsockopt(int fd, int level, int optname, nint optval, ref int optlen);

    [LibraryImport("libproc", SetLastError = true)]
    private static partial int proc_pidpath(int pid, nint buffer, uint bufferSize);

    public static (int Pid, string? Path) Of(Socket socket)
    {
        try
        {
            int fd = (int)socket.Handle;
            if (OperatingSystem.IsMacOS())
            {
                int pid = 0, len = sizeof(int);
                nint buf = Marshal.AllocHGlobal(sizeof(int));
                try
                {
                    if (getsockopt(fd, 0 /* SOL_LOCAL */, 2 /* LOCAL_PEERPID */, buf, ref len) != 0) return (0, null);
                    pid = Marshal.ReadInt32(buf);
                }
                finally { Marshal.FreeHGlobal(buf); }
                nint path = Marshal.AllocHGlobal(4096);
                try
                {
                    int n = proc_pidpath(pid, path, 4096);
                    return (pid, n > 0 ? Marshal.PtrToStringUTF8(path, n) : null);
                }
                finally { Marshal.FreeHGlobal(path); }
            }
            if (OperatingSystem.IsLinux())
            {
                int len = 12; // struct ucred { pid_t pid; uid_t uid; gid_t gid; }
                nint buf = Marshal.AllocHGlobal(len);
                try
                {
                    if (getsockopt(fd, 1 /* SOL_SOCKET */, 17 /* SO_PEERCRED */, buf, ref len) != 0) return (0, null);
                    int pid = Marshal.ReadInt32(buf);
                    string? exe = null;
                    try { exe = File.ResolveLinkTarget($"/proc/{pid}/exe", returnFinalTarget: true)?.FullName; } catch (IOException) { } catch (UnauthorizedAccessException) { }
                    return (pid, exe);
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            Log.Debug($"peer identity unavailable: {ex.Message}");
        }
        return (0, null);
    }
}
