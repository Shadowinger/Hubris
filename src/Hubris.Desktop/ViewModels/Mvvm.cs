using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;

namespace Hubris.Desktop.ViewModels;

/// <summary>Minimal INotifyPropertyChanged base – no toolkit, no reflection.</summary>
public abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        Raise(name);
        return true;
    }

    protected void Raise([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Func<object?, bool>? _canExecute;

    public RelayCommand(Action execute, Func<bool>? canExecute = null)
        : this(_ => execute(), canExecute is null ? null : _ => canExecute()) { }

    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;
    public void Execute(object? parameter) => _execute(parameter);
    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

public sealed class AsyncCommand : ICommand
{
    private readonly Func<Task> _execute;
    private readonly Func<bool>? _canExecute;
    private bool _running;

    public AsyncCommand(Func<Task> execute, Func<bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    /// <summary>What a command threw; the main view model shows it where the user is looking.</summary>
    public static event Action<Exception>? Failed;

    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? parameter) => !_running && (_canExecute?.Invoke() ?? true);

    public async void Execute(object? parameter)
    {
        if (!CanExecute(parameter)) return;
        _running = true; RaiseCanExecuteChanged();
        try { await _execute(); }
        catch (Exception ex) { Failed?.Invoke(ex); }
        finally { _running = false; RaiseCanExecuteChanged(); }
    }

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

public static class Fmt
{
    public static string Bytes(long? b) => b is null ? "–" : b < 1024 * 1024 ? $"{b / 1024.0:0} KB" : $"{b / 1048576.0:0.0} MB";

    public static string Duration(double? seconds)
    {
        if (seconds is null) return "–";
        var t = TimeSpan.FromSeconds(seconds.Value);
        if (t.TotalHours >= 1) return $"{(int)t.TotalHours}h {t.Minutes:00}m";
        if (t.TotalMinutes >= 1) return $"{t.Minutes}m {t.Seconds:00}s";
        return $"{t.Seconds}s";
    }

    public static string Ms(double? ms) => ms is null ? "" : ms < 1 ? "<1 ms" : ms < 1000 ? $"{ms:0} ms" : $"{ms / 1000:0.0} s";

    public static string LocalTime(string? iso)
    {
        if (iso is not null && DateTime.TryParse(iso, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out var dt))
            return dt.ToLocalTime().ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
        return DateTime.Now.ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
    }

    public static string Trim(string? s, int max) => s is null ? "" : s.Length <= max ? s : string.Concat(s.AsSpan(0, max), "…");
}
