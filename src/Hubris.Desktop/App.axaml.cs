using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Hubris.Desktop.Services;
using Hubris.Desktop.ViewModels;
using Hubris.Desktop.Views;

namespace Hubris.Desktop;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // Pure DI: build the object graph by hand, no container.
            var discovery = new HubDiscovery();
            var launcher = new HubLauncher();
            var vm = new MainViewModel(discovery, launcher);
            desktop.MainWindow = new MainWindow { DataContext = vm };
            desktop.ShutdownRequested += (_, _) => vm.Dispose();
            vm.Start();
        }
        base.OnFrameworkInitializationCompleted();
    }
}
