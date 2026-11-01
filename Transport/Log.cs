namespace McpHub.Transport;

/// <summary>All diagnostics go to stderr. stdout is reserved for JSON-RPC frames.</summary>
public static class Log
{
    private static readonly object Gate = new();
    private const string Prefix = "[McpHub] ";

    public static bool Verbose { get; set; }

    public static void Info(string message) => Write(Prefix, message);
    public static void Warn(string message) => Write(Prefix + "WARN ", message);
    public static void Error(string message) => Write(Prefix + "ERROR ", message);
    public static void Debug(string message) { if (Verbose) Write(Prefix + "DEBUG ", message); }

    private static void Write(string prefix, string message)
    {
        try
        {
            lock (Gate)
            {
                Console.Error.Write(prefix);
                Console.Error.WriteLine(message);
            }
        }
        catch
        {
            // stderr closed; nothing sensible left to do.
        }
    }
}
