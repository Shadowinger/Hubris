using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Platform.Storage;
using Hubris.Desktop.ViewModels;

namespace Hubris.Desktop.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => WireViewServices();
    }

    private void WireViewServices()
    {
        if (DataContext is not MainViewModel vm) return;
        vm.Config.PickFolder = PickFolderAsync;
        vm.Config.PickFile = PickFileAsync;
        vm.Config.CopyToClipboard = CopyAsync;
    }

    private async Task<string?> PickFolderAsync()
    {
        var top = GetTopLevel(this);
        if (top is null) return null;
        var picked = await top.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = "Choose VS Code workspace folder", AllowMultiple = false });
        return picked.Count > 0 ? picked[0].TryGetLocalPath() : null;
    }

    private async Task<string?> PickFileAsync()
    {
        var top = GetTopLevel(this);
        if (top is null) return null;
        var picked = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Locate the Hubris server executable", AllowMultiple = false });
        return picked.Count > 0 ? picked[0].TryGetLocalPath() : null;
    }

    private async Task CopyAsync(string text)
    {
        var clipboard = GetTopLevel(this)?.Clipboard;
        if (clipboard is null) return;
        await clipboard.SetTextAsync(text);
    }
}
