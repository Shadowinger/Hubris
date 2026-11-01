using System.Collections.ObjectModel;
using System.Text;
using System.Diagnostics;
using System.Text.Json.Nodes;
using Hubris.Cli;
using Hubris.Config;
using Hubris.Control;
using Hubris.Desktop.Services;

namespace Hubris.Desktop.ViewModels;

/// <summary>Configurator + launcher: builds the server command line, writes client configs, starts test instances.</summary>
public sealed class ConfigViewModel : ObservableObject
{
    private readonly HubLauncher _launcher;
    private readonly StringBuilder _log = new();

    private string _serverPath;
    private bool _isBypass;
    private bool _compact = true;
    private bool _verbose;
    private bool _noControl;
    private string _approvalTimeout = "120";
    private string _workspaceFolder = "";
    private string _logText = "";
    private string _lastResult = "";

    public ConfigViewModel(HubLauncher launcher)
    {
        _launcher = launcher;
        _serverPath = HubLauncher.FindServerExecutable() ?? "";
        _launcher.Output += line => Avalonia.Threading.Dispatcher.UIThread.Post(() => AppendLog(line));

        AddBridgeCommand = new RelayCommand(() => { Bridges.Add(NewBridge()); });
        InstallClaudeCommand = new RelayCommand(InstallClaude, () => ServerPathValid);
        InstallVsCodeCommand = new RelayCommand(InstallVsCode, () => ServerPathValid && Directory.Exists(_workspaceFolder));
        LaunchTestCommand = new RelayCommand(LaunchTest, () => ServerPathValid);
        BrowseWorkspaceCommand = new AsyncCommand(BrowseWorkspaceAsync);
        BrowseServerCommand = new AsyncCommand(BrowseServerAsync);
        CopyCommandCommand = new AsyncCommand(() => CopyToClipboard?.Invoke(CommandPreview) ?? Task.CompletedTask);
        ClearLogCommand = new RelayCommand(() => { _log.Clear(); LogText = ""; });
        SetSafeCommand = new RelayCommand(() => IsBypass = false);
        SetBypassCommand = new RelayCommand(() => IsBypass = true);

        ScanClientsCommand = new RelayCommand(ScanClients);
        ScanProjectsCommand = new RelayCommand(ScanProjects, () => Directory.Exists(_projectRoot));
        BrowseProjectRootCommand = new AsyncCommand(async () => { if (PickFolder is { } pick && await pick() is { } dir) ProjectRoot = dir; });
        SaveBridgesCommand = new RelayCommand(SaveBridges);
        LoadBridges();
        ScanClients();
    }

    /// <summary>Installed by MainViewModel: asks every connected hub to pick up config.json; returns how many were told.</summary>
    public Func<Task<int>>? ReloadRunningHubs { get; set; }

    public ObservableCollection<DetectedClientRow> Clients { get; } = new();
    private string _projectRoot = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    public string ProjectRoot { get => _projectRoot; set { if (Set(ref _projectRoot, value)) ScanProjectsCommand.RaiseCanExecuteChanged(); } }
    public RelayCommand ScanProjectsCommand { get; }
    public AsyncCommand BrowseProjectRootCommand { get; }
    public bool NoClients => Clients.Count == 0;
    public string ConfigPath => HubrisPaths.ConfigPath;
    public RelayCommand ScanClientsCommand { get; }
    public RelayCommand SaveBridgesCommand { get; }

    private void LoadBridges()
    {
        Bridges.Clear();
        try
        {
            foreach (var b in HubrisConfigFile.Load().Bridges)
            {
                var row = NewBridge();
                row.Name = b.Name; row.Command = b.Command; row.Args = string.Join(' ', b.Args.Select(Quote)); row.Source = b.Source ?? "";
                row.EnvCount = b.Env?.Count ?? 0;
                Bridges.Add(row);
            }
        }
        catch (Exception ex) { AppendLog($"config.json unreadable: {ex.Message}"); }
    }

    private void SaveBridges()
    {
        var cfg = new HubrisConfig();
        var existing = SafeLoad();
        foreach (var row in Bridges)
        {
            if (string.IsNullOrWhiteSpace(row.Name) || string.IsNullOrWhiteSpace(row.Command)) continue;
            var prev = existing.Bridges.Find(b => b.Name == row.Name.Trim());
            cfg.Bridges.Add(new BridgeConfig
            {
                Name = row.Name.Trim(), Command = row.Command.Trim(), Args = SplitArgs(row.Args),
                Env = prev?.Env, Source = prev?.Source ?? (string.IsNullOrEmpty(row.Source) ? null : row.Source),
            });
        }
        HubrisConfigFile.Save(cfg);
        LastResult = $"✓ {cfg.Bridges.Count} bridge(s) saved to {ConfigPath}.";
        AppendLog(LastResult);
        _ = NotifyHubsAsync();
    }

    private static HubrisConfig SafeLoad()
    {
        try { return HubrisConfigFile.Load(); } catch (Exception) { return new HubrisConfig(); }
    }

    private void ScanClients()
    {
        Clients.Clear();
        foreach (var c in ClientConfigScanner.Scan(string.IsNullOrEmpty(_workspaceFolder) ? null : _workspaceFolder))
            Clients.Add(new DetectedClientRow(c, ImportClient, RestoreClient));
        Raise(nameof(NoClients));
    }

    /// <summary>Appends project-level configs under ProjectRoot (depth 4); global rows stay.</summary>
    private void ScanProjects()
    {
        for (int i = Clients.Count - 1; i >= 0; i--) if (Clients[i].Client.Kind.IsProjectLevel) Clients.RemoveAt(i);
        var found = ClientConfigScanner.ScanProjects(_projectRoot);
        foreach (var c in found) Clients.Add(new DetectedClientRow(c, ImportClient, RestoreClient));
        LastResult = $"{found.Count} project config(s) under {_projectRoot}.";
        Raise(nameof(NoClients));
    }

    /// <summary>A project file may be emptied when that client's global config already routes through Hubris.</summary>
    private bool GlobalIsGateway(DetectedClient client)
        => client.Kind.GlobalKindId is { } g && Clients.Any(r => r.Client.Kind.Id == g && r.IsGateway);

    private void ImportClient(DetectedClient client)
    {
        if (!ServerPathValid) { LastResult = "✗ Point 'Server binary' at the Hubris executable first."; return; }
        if (RunningClientProcess(client.Kind) is { } running)
        {
            LastResult = $"✗ {client.Kind.Name}: quit '{running}' first — it keeps this config in memory and would write the old server list back over the takeover.";
            AppendLog(LastResult);
            return;
        }
        try
        {
            var cfg = SafeLoad();
            var result = ClientConfigHijacker.Import(client, cfg);
            HubrisConfigFile.Save(cfg);
            bool empty = GlobalIsGateway(client);
            string backup = ClientConfigHijacker.Hijack(client, _serverPath, BuildServerArgs(), empty);
            LastResult = $"✓ {client.Kind.Name}: imported {result.Added.Count} bridge(s) ({string.Join(", ", result.Added)}), {result.Skipped.Count} already present; {(empty ? "server block emptied (global client already routes through Hubris)" : "config rewritten")}, {client.ProjectBlocksWithServers} project block(s) cleared, backup {Path.GetFileName(backup)}. Restart the client to pick it up.";
            AppendLog(LastResult);
            LoadBridges();
            RescanKeepingProjects();
            _ = NotifyHubsAsync();
        }
        catch (Exception ex)
        {
            LastResult = $"✗ Import failed: {ex.Message}";
            AppendLog(LastResult);
        }
    }

    private void RestoreClient(DetectedClient client)
    {
        try
        {
            string? used = ClientConfigHijacker.Restore(client);
            LastResult = used is null ? $"✗ {client.Kind.Name}: no Hubris snapshot or backup for {client.Path}" : $"✓ {client.Kind.Name}: restored from {Path.GetFileName(used)}. Restart the client to pick it up.";
            AppendLog(LastResult);
            RescanKeepingProjects();
        }
        catch (Exception ex)
        {
            LastResult = $"✗ Restore failed: {ex.Message}";
            AppendLog(LastResult);
        }
    }

    private void RescanKeepingProjects()
    {
        bool hadProjects = Clients.Any(r => r.Client.Kind.IsProjectLevel);
        ScanClients();
        if (hadProjects) ScanProjects();
    }

    private async Task NotifyHubsAsync()
    {
        if (ReloadRunningHubs is null) return;
        int n = await ReloadRunningHubs();
        if (n > 0) Avalonia.Threading.Dispatcher.UIThread.Post(() => AppendLog($"asked {n} running hub(s) to reload config.json"));
    }

    /// <summary>Installed by the view: opens a folder picker and returns the chosen path.</summary>
    public Func<Task<string?>>? PickFolder { get; set; }
    public Func<Task<string?>>? PickFile { get; set; }
    public Func<string, Task>? CopyToClipboard { get; set; }

    // ---------------------------------------------------------------- fields
    public string ServerPath { get => _serverPath; set { if (Set(ref _serverPath, value)) { Raise(nameof(ServerPathValid)); Raise(nameof(CommandPreview)); RaiseCommands(); } } }
    public bool ServerPathValid => File.Exists(_serverPath);
    public bool IsBypass { get => _isBypass; set { if (Set(ref _isBypass, value)) { Raise(nameof(IsSafe)); Raise(nameof(CommandPreview)); } } }
    public bool IsSafe => !_isBypass;
    public bool Compact { get => _compact; set { if (Set(ref _compact, value)) Raise(nameof(CommandPreview)); } }
    public bool Verbose { get => _verbose; set { if (Set(ref _verbose, value)) Raise(nameof(CommandPreview)); } }
    public bool NoControl { get => _noControl; set { if (Set(ref _noControl, value)) Raise(nameof(CommandPreview)); } }
    public string ApprovalTimeout { get => _approvalTimeout; set { if (Set(ref _approvalTimeout, value)) Raise(nameof(CommandPreview)); } }
    public string WorkspaceFolder { get => _workspaceFolder; set { if (Set(ref _workspaceFolder, value)) { Raise(nameof(VsCodeConfigPath)); RaiseCommands(); } } }
    public string ClaudeConfigPath => ClientConfigScanner.ClaudeDesktopPath(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
    public string VsCodeConfigPath => string.IsNullOrEmpty(_workspaceFolder) ? "(choose a workspace folder)" : Path.Combine(_workspaceFolder, ".vscode", "mcp.json");
    public string LogText { get => _logText; private set => Set(ref _logText, value); }
    public string LastResult { get => _lastResult; private set => Set(ref _lastResult, value); }
    public ObservableCollection<BridgeRow> Bridges { get; } = new();

    public string CommandPreview
    {
        get
        {
            var sb = new StringBuilder();
            sb.Append(string.IsNullOrEmpty(_serverPath) ? "Hubris" : Quote(_serverPath));
            foreach (var a in BuildServerArgs()) sb.Append(' ').Append(Quote(a));
            return sb.ToString();
        }
    }

    // ---------------------------------------------------------------- commands
    public RelayCommand AddBridgeCommand { get; }
    public RelayCommand InstallClaudeCommand { get; }
    public RelayCommand InstallVsCodeCommand { get; }
    public RelayCommand LaunchTestCommand { get; }
    public AsyncCommand BrowseWorkspaceCommand { get; }
    public AsyncCommand BrowseServerCommand { get; }
    public AsyncCommand CopyCommandCommand { get; }
    public RelayCommand ClearLogCommand { get; }
    public RelayCommand SetSafeCommand { get; }
    public RelayCommand SetBypassCommand { get; }

    private BridgeRow NewBridge()
    {
        var row = new BridgeRow();
        row.RemoveCommand = new RelayCommand(() => Bridges.Remove(row));
        row.PropertyChanged += (_, _) => Raise(nameof(CommandPreview));
        return row;
    }

    public List<string> BuildServerArgs()
    {
        var list = new List<string> { "--stdio" };
        if (_isBypass) list.Add("--mode=bypass");
        if (_compact) list.Add("--compact");
        if (_verbose) list.Add("--verbose");
        if (_noControl) list.Add("--no-control");
        if (double.TryParse(_approvalTimeout, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var t) && t != 120 && t >= 1)
            list.Add($"--approval-timeout={t.ToString(System.Globalization.CultureInfo.InvariantCulture)}");
        return list; // bridges live in ~/.hubris/config.json, not on the command line
    }

    private void InstallClaude()
    {
        bool ok = ClientConfigHijacker.MergeServerEntry(ClaudeConfigPath, "mcpServers", ClientConfigHijacker.ServerKey, new JsonObject { ["command"] = _serverPath, ["args"] = ArgsNode() });
        LastResult = ok ? $"✓ Registered 'hubris' in {ClaudeConfigPath}. Restart Claude Desktop to pick it up." : "✗ Failed to write Claude Desktop config (see log).";
        AppendLog(LastResult);
    }

    private void InstallVsCode()
    {
        bool ok = ClientConfigHijacker.MergeServerEntry(Path.Combine(_workspaceFolder, ".vscode", "mcp.json"), "servers", ClientConfigHijacker.ServerKey, new JsonObject { ["type"] = "stdio", ["command"] = _serverPath, ["args"] = ArgsNode() });
        LastResult = ok ? $"✓ Registered 'hubris' in {VsCodeConfigPath}." : "✗ Failed to write .vscode/mcp.json (see log).";
        AppendLog(LastResult);
    }

    private JsonArray ArgsNode()
    {
        var arr = new JsonArray();
        foreach (var a in BuildServerArgs()) arr.Add((JsonNode?)JsonValue.Create(a));
        return arr;
    }

    /// <summary>Clients keep their config in memory and write it back later; a hijack while they run can be undone silently.</summary>
    private static string? RunningClientProcess(ClientKind kind)
    {
        string[] names = kind.Id switch
        {
            "claude-desktop" => ["Claude"],
            "claude-code" or "project-mcp" => ["claude"],
            "cursor" or "cursor-project" => ["Cursor"],
            "windsurf" => ["Windsurf"],
            _ => [],
        };
        foreach (var n in names)
        {
            var procs = Process.GetProcessesByName(n);
            bool any = procs.Length > 0;
            foreach (var p in procs) p.Dispose();
            if (any) return n;
        }
        return null;
    }

    private void LaunchTest()
    {
        try
        {
            var args = BuildServerArgs();
            if (args.Contains("--no-control")) { LastResult = "Test instance needs the control socket; untick 'disable control socket'."; return; }
            int pid = _launcher.Launch(_serverPath, args, string.IsNullOrEmpty(_workspaceFolder) ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) : _workspaceFolder);
            LastResult = $"✓ Test instance started (pid {pid}); it will appear in the sidebar in a moment.";
            AppendLog(LastResult);
        }
        catch (Exception ex)
        {
            LastResult = $"✗ Launch failed: {ex.Message}";
            AppendLog(LastResult);
        }
    }

    private async Task BrowseWorkspaceAsync()
    {
        if (PickFolder is null) return;
        string? dir = await PickFolder();
        if (!string.IsNullOrEmpty(dir)) WorkspaceFolder = dir;
    }

    private async Task BrowseServerAsync()
    {
        if (PickFile is null) return;
        string? file = await PickFile();
        if (!string.IsNullOrEmpty(file)) ServerPath = file;
    }

    private void AppendLog(string line)
    {
        _log.Append(line).Append('\n');
        if (_log.Length > 64 * 1024) _log.Remove(0, _log.Length - 48 * 1024);
        LogText = _log.ToString();
    }

    private void RaiseCommands()
    {
        InstallClaudeCommand.RaiseCanExecuteChanged();
        InstallVsCodeCommand.RaiseCanExecuteChanged();
        LaunchTestCommand.RaiseCanExecuteChanged();
    }

    private static string Quote(string s) => s.Length > 0 && s.IndexOfAny([' ', '"', '\'']) < 0 ? s : "\"" + s.Replace("\"", "\\\"") + "\"";

    /// <summary>Shell-ish split: whitespace separated, double/single quotes group.</summary>
    public static List<string> SplitArgs(string text)
    {
        var result = new List<string>();
        var cur = new StringBuilder();
        char quote = '\0';
        bool any = false;
        foreach (char c in text)
        {
            if (quote != '\0') { if (c == quote) quote = '\0'; else cur.Append(c); continue; }
            if (c is '"' or '\'') { quote = c; any = true; continue; }
            if (char.IsWhiteSpace(c)) { if (any || cur.Length > 0) { result.Add(cur.ToString()); cur.Clear(); any = false; } continue; }
            cur.Append(c);
        }
        if (any || cur.Length > 0) result.Add(cur.ToString());
        return result;
    }
}

public sealed class BridgeRow : ObservableObject
{
    private string _name = "";
    private string _command = "";
    private string _args = "";
    private string _source = "";
    private int _envCount;

    public string Name { get => _name; set => Set(ref _name, value); }
    public string Command { get => _command; set => Set(ref _command, value); }
    public string Args { get => _args; set => Set(ref _args, value); }
    public string Source { get => _source; set { if (Set(ref _source, value)) Raise(nameof(HasSource)); } }
    public bool HasSource => _source.Length > 0;
    public int EnvCount { get => _envCount; set { if (Set(ref _envCount, value)) { Raise(nameof(EnvText)); Raise(nameof(HasEnv)); } } }
    public bool HasEnv => _envCount > 0;
    public string EnvText => $"{_envCount} env";
    public RelayCommand? RemoveCommand { get; set; }
}

public sealed class DetectedClientRow
{
    public DetectedClientRow(DetectedClient client, Action<DetectedClient> import, Action<DetectedClient> restore)
    {
        Client = client;
        Name = client.Kind.Name;
        Path = client.Path;
        ServerCount = client.Servers.Count;
        ServersText = (ServerCount == 1 ? "1 server" : $"{ServerCount} servers") + (client.ProjectBlocksWithServers > 0 ? $" · {client.ProjectBlocksWithServers} project block(s)" : "");
        ServerNames = string.Join(", ", client.Servers.Select(s => s.Scope.Length > 0 ? $"{s.Name} ({System.IO.Path.GetFileName(s.Scope.TrimEnd('/'))})" : s.Name).Distinct());
        IsGateway = client.IsGateway;
        HasBackup = ClientConfigHijacker.HasRestorePoint(client.Path);
        ImportCommand = new RelayCommand(() => import(client), () => !IsGateway);
        RestoreCommand = new RelayCommand(() => restore(client), () => HasBackup);
    }

    public DetectedClient Client { get; }
    public string Name { get; }
    public string Path { get; }
    public int ServerCount { get; }
    public string ServersText { get; }
    public string ServerNames { get; }
    public bool HasServers => ServerCount > 0;
    public bool IsGateway { get; }
    public bool HasBackup { get; }
    public string ActionText => IsGateway ? "Already routed through Hubris" : ServerCount == 0 ? "Register Hubris" : Client.ProjectBlocksWithServers > 0 ? "Import & take over" : "Import & hijack";
    public RelayCommand ImportCommand { get; }
    public RelayCommand RestoreCommand { get; }
}
