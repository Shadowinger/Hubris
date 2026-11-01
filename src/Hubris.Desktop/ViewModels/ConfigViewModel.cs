using System.Collections.ObjectModel;
using System.Text;
using Hubris.Cli;
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

        Bridges.CollectionChanged += (_, _) => Raise(nameof(CommandPreview));
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
    public string ClaudeConfigPath => AutoInstaller.ClaudeConfigPath() ?? "(unsupported OS)";
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
        foreach (var b in Bridges)
        {
            if (string.IsNullOrWhiteSpace(b.Name) || string.IsNullOrWhiteSpace(b.Command)) continue;
            list.Add($"--bridge={b.Name.Trim()}:{b.Command.Trim()}");
            list.AddRange(SplitArgs(b.Args));
        }
        return list;
    }

    private void InstallClaude()
    {
        int rc = AutoInstaller.InstallClaude(_serverPath, BuildServerArgs());
        LastResult = rc == 0 ? $"✓ Registered 'hubris' in {ClaudeConfigPath}. Restart Claude Desktop to pick it up." : "✗ Failed to write Claude Desktop config (see log).";
        AppendLog(LastResult);
    }

    private void InstallVsCode()
    {
        int rc = AutoInstaller.InstallVsCode(_workspaceFolder, _serverPath, BuildServerArgs());
        LastResult = rc == 0 ? $"✓ Registered 'hubris' in {VsCodeConfigPath}." : "✗ Failed to write .vscode/mcp.json (see log).";
        AppendLog(LastResult);
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

    public string Name { get => _name; set => Set(ref _name, value); }
    public string Command { get => _command; set => Set(ref _command, value); }
    public string Args { get => _args; set => Set(ref _args, value); }
    public RelayCommand? RemoveCommand { get; set; }
}
