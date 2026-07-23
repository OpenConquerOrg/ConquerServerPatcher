using ConquerRsaTool.Core.Crypto;
using ConquerRsaTool.Core.Patching;
using Microsoft.Win32;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Automation;

namespace ConquerRsaTool.Wpf;

public partial class MainWindow : Window
{
    private readonly RsaKeyService _keys = new();
    private readonly ConquerDatService _dat = new();
    private readonly ConquerBinaryService _binary = new();
    private readonly string _keyDirectory;
    private readonly string _publicKeyPath;
    private readonly string _privateKeyPath;
    private readonly string _originalClientPublicKeyPath;
    private string? _lastOutputPath;

    public MainWindow()
    {
        InitializeComponent();

        _keyDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ConquerServerPatcher",
            "keys");
        _publicKeyPath = Path.Combine(_keyDirectory, "public_key.pem");
        _privateKeyPath = Path.Combine(_keyDirectory, "private_key.pem");
        _originalClientPublicKeyPath = Path.Combine(
            _keyDirectory,
            "original_client_public_key.pem");

        RefreshKeyStatus();
        Log("Application ready. The original client will never be overwritten.");
    }

    private void MinimizeWindow_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState.Minimized;

    private void MaximizeWindow_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized
            ? WindowState.Normal
            : WindowState.Maximized;

    private void CloseWindow_Click(object sender, RoutedEventArgs e) => Close();

    private void Window_StateChanged(object? sender, EventArgs e)
    {
        var maximized = WindowState == WindowState.Maximized;
        MaximizeWindowButton.Content = maximized ? "\uE923" : "\uE922";
        AutomationProperties.SetName(
            MaximizeWindowButton,
            maximized ? "Restore" : "Maximize");
        RootBorder.CornerRadius = maximized
            ? new CornerRadius(0)
            : new CornerRadius(12);
    }

    private async Task RunAsync(string operation, Action action)
    {
        try
        {
            IsEnabled = false;
            Log($"{operation}...");
            await Task.Run(action);
            Log($"{operation}: completed.");
        }
        catch (Exception ex)
        {
            Log($"ERROR: {ex.Message}");
            var isAlreadyPatched = ex is ClientAlreadyPatchedException;
            MessageBox.Show(
                this,
                ex.Message,
                isAlreadyPatched ? "Client already patched" : "Operation failed",
                MessageBoxButton.OK,
                isAlreadyPatched ? MessageBoxImage.Information : MessageBoxImage.Error);
        }
        finally
        {
            IsEnabled = true;
            RefreshKeyStatus();
        }
    }

    private async void SelectClient_Click(object sender, RoutedEventArgs e)
    {
        var exePath = Open(
            "Conquer client|Conquer.exe;*.exe|Executable files|*.exe");
        if (exePath is null)
            return;

        ExePath.Text = exePath;
        OutputFileName.Text =
            $"{Path.GetFileNameWithoutExtension(exePath)}Patched.exe";
        ResultPanel.Visibility = Visibility.Collapsed;
        ClientStatusText.Text = "Checking the client...";
        ClientStatusText.Foreground =
            (System.Windows.Media.Brush)FindResource("MutedTextBrush");
        ApplyPatchButton.IsEnabled = false;

        await RunAsync("Checking client", () =>
        {
            if (File.Exists(_publicKeyPath) &&
                _binary.IsPatchedWithPublicKey(exePath, _publicKeyPath))
            {
                Dispatcher.Invoke(() =>
                {
                    ClientStatusText.Text =
                        "This executable is already patched with the current permanent key.";
                    ClientStatusText.Foreground =
                        (System.Windows.Media.Brush)FindResource("SuccessBrush");
                });
                throw new ClientAlreadyPatchedException(
                    "The selected executable is already patched with the current key. " +
                    "It does not need to be patched again.");
            }

            var analysis = _binary.Analyze(exePath);
            if (!analysis.Supported)
            {
                Dispatcher.Invoke(() =>
                {
                    ClientStatusText.Text =
                        "This does not appear to be a compatible original client, " +
                        "or it was patched with a different key.";
                    ClientStatusText.Foreground = System.Windows.Media.Brushes.DarkRed;
                });
                throw new InvalidDataException(analysis.Message);
            }

            Dispatcher.Invoke(() =>
            {
                ClientStatusText.Text =
                    "Compatible original client. Review the name and apply the patch.";
                ClientStatusText.Foreground =
                    (System.Windows.Media.Brush)FindResource("SuccessBrush");
                ApplyPatchButton.IsEnabled = true;
            });
        });
    }

    private async void ApplyPatch_Click(object sender, RoutedEventArgs e)
    {
        var exePath = RequireSelectedClient();
        if (exePath is null)
            return;

        ResultPanel.Visibility = Visibility.Collapsed;
        ClientStatusText.Text = "Applying patch...";
        var bypassPlayExe = BypassPlayExe.IsChecked == true;
        var requestedOutputName = OutputFileName.Text.Trim();

        await RunAsync("Preparing client", () =>
        {
            var created = EnsureManagedKeyPair();
            Log(created
                ? "A permanent server key pair was generated."
                : "Using the existing permanent server key.");

            if (_binary.IsPatchedWithPublicKey(exePath, _publicKeyPath))
            {
                Dispatcher.Invoke(() =>
                {
                    ClientStatusText.Text =
                        "This executable is already patched with the current permanent key.";
                    ClientStatusText.Foreground =
                        (System.Windows.Media.Brush)FindResource("SuccessBrush");
                });
                throw new ClientAlreadyPatchedException(
                    "The selected executable is already patched with the current key. " +
                    "No changes were made.");
            }

            var analysis = _binary.Analyze(exePath);
            if (!analysis.Supported)
                throw new InvalidDataException(analysis.Message);

            _binary.ExtractPublicKey(exePath, _originalClientPublicKeyPath);
            Log("The client's original public key was saved for DAT decryption.");

            var outputFileName = ResolveOutputFileName(exePath, requestedOutputName);
            var outputPath = Path.Combine(
                Path.GetDirectoryName(exePath)!,
                outputFileName);

            var result = _binary.Patch(
                exePath,
                _publicKeyPath,
                outputPath,
                bypassPlayExe);

            Dispatcher.Invoke(() =>
            {
                _lastOutputPath = result.OutputPath;
                ClientStatusText.Text =
                    "Original client detected and patched successfully.";
                ClientStatusText.Foreground =
                    (System.Windows.Media.Brush)FindResource("SuccessBrush");
                ResultText.Text =
                    $"Saved to {result.OutputPath}. {result.PlayExeBypassMessage}";
                ResultPanel.Visibility = Visibility.Visible;
            });
        });
    }

    private async void Analyze_Click(object sender, RoutedEventArgs e)
    {
        var path = RequireSelectedClient();
        if (path is null)
            return;

        await RunAsync("Analyzing client", () =>
        {
            if (File.Exists(_publicKeyPath) &&
                _binary.IsPatchedWithPublicKey(path, _publicKeyPath))
            {
                Log("The client is already patched with the current permanent key.");
                Dispatcher.Invoke(() =>
                {
                    ClientStatusText.Text =
                        "This executable is already patched with the current permanent key.";
                    ClientStatusText.Foreground =
                        (System.Windows.Media.Brush)FindResource("SuccessBrush");
                });
                return;
            }

            var result = _binary.Analyze(path);
            Log($"Compatible: {(result.Supported ? "yes" : "no")}. {result.Message}");
            if (!result.Supported)
                throw new InvalidDataException(result.Message);
        });
    }

    private async void ExtractKey_Click(object sender, RoutedEventArgs e)
    {
        var path = RequireSelectedClient();
        if (path is null)
            return;

        var output = Save("PEM key|*.pem", "original_public_key.pem");
        if (output is null)
            return;

        await RunAsync(
            "Extracting original key",
            () => _binary.ExtractPublicKey(path, output));
    }

    private async void DecryptDat_Click(object sender, RoutedEventArgs e)
    {
        var input = Open("DAT files|*.dat|All files|*.*");
        if (input is null)
            return;

        var output = DefaultOutput(input, "_decrypted");
        await RunAsync("Decrypting DAT", () =>
        {
            if (!File.Exists(_originalClientPublicKeyPath))
            {
                throw new InvalidDataException(
                    "The client's original key has not been extracted. " +
                    "Choose and patch the original Conquer.exe first.");
            }

            _dat.Decrypt(input, _originalClientPublicKeyPath, output);
            Log($"File saved to {output}");
        });
    }

    private async void EncryptDat_Click(object sender, RoutedEventArgs e)
    {
        var input = Open("DAT files|*.dat|All files|*.*");
        if (input is null)
            return;

        var output = DefaultOutput(input, "_encrypted");
        await RunAsync("Encrypting DAT", () =>
        {
            EnsureManagedKeyPair();
            _dat.Encrypt(input, _privateKeyPath, output);
            Log($"File saved to {output}");
        });
    }

    private bool EnsureManagedKeyPair()
    {
        var publicExists = File.Exists(_publicKeyPath);
        var privateExists = File.Exists(_privateKeyPath);

        if (!publicExists && !privateExists)
        {
            _keys.GenerateKeyPair(_publicKeyPath, _privateKeyPath);
            return true;
        }

        if (!publicExists || !privateExists)
        {
            throw new InvalidDataException(
                $"The key store is incomplete. Check this folder: {_keyDirectory}");
        }

        var publicKey = _keys.LoadPublic(_publicKeyPath);
        var privateKey = _keys.LoadPrivate(_privateKeyPath);
        if (publicKey.Modulus is null ||
            privateKey.Modulus is null ||
            !CryptographicOperations.FixedTimeEquals(
                publicKey.Modulus,
                privateKey.Modulus))
        {
            throw new InvalidDataException(
                $"The public and private keys are not a valid pair. Check: {_keyDirectory}");
        }

        return false;
    }

    private void RefreshKeyStatus()
    {
        if (File.Exists(_publicKeyPath) && File.Exists(_privateKeyPath))
        {
            KeyStatusText.Text =
                "Permanent key available. It will be reused automatically.";
            KeyStatusText.Foreground =
                (System.Windows.Media.Brush)FindResource("SuccessBrush");
        }
        else if (File.Exists(_publicKeyPath) || File.Exists(_privateKeyPath))
        {
            KeyStatusText.Text =
                "The key store is incomplete. Open the folder to review it.";
            KeyStatusText.Foreground = System.Windows.Media.Brushes.DarkRed;
        }
        else
        {
            KeyStatusText.Text =
                "A permanent key will be generated when the first client is patched.";
            KeyStatusText.Foreground =
                (System.Windows.Media.Brush)FindResource("MutedTextBrush");
        }
    }

    private string? RequireSelectedClient()
    {
        if (!string.IsNullOrWhiteSpace(ExePath.Text) && File.Exists(ExePath.Text))
            return Path.GetFullPath(ExePath.Text);

        MessageBox.Show(
            this,
            "Choose a client first.",
            "No client selected",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
        return null;
    }

    private void OpenKeysFolder_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(_keyDirectory);
        OpenFolder(_keyDirectory);
    }

    private void OpenOutputFolder_Click(object sender, RoutedEventArgs e)
    {
        if (_lastOutputPath is not null)
            OpenFolder(Path.GetDirectoryName(_lastOutputPath)!);
    }

    private static void OpenFolder(string path) =>
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"")
        {
            UseShellExecute = true
        });

    private void Log(string message)
    {
        Dispatcher.Invoke(() =>
        {
            LogBox.AppendText(
                $"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
            LogBox.ScrollToEnd();
        });
    }

    private static string? Open(string filter)
    {
        var dialog = new OpenFileDialog
        {
            Filter = filter,
            CheckFileExists = true
        };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    private static string? Save(string filter, string fileName)
    {
        var dialog = new SaveFileDialog
        {
            Filter = filter,
            FileName = fileName,
            AddExtension = true
        };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    private static string DefaultOutput(string path, string suffix) =>
        Path.Combine(
            Path.GetDirectoryName(path)!,
            Path.GetFileNameWithoutExtension(path) +
            suffix +
            Path.GetExtension(path));

    private static string ResolveOutputFileName(
        string sourcePath,
        string requestedName)
    {
        var outputName = string.IsNullOrWhiteSpace(requestedName)
            ? $"{Path.GetFileNameWithoutExtension(sourcePath)}Patched.exe"
            : requestedName;

        if (outputName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            !string.Equals(
                outputName,
                Path.GetFileName(outputName),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "The output name is invalid. Enter a file name without folders.");
        }

        if (string.IsNullOrEmpty(Path.GetExtension(outputName)))
        {
            outputName += ".exe";
        }
        else if (!string.Equals(
                     Path.GetExtension(outputName),
                     ".exe",
                     StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "The output file must use the .exe extension.");
        }

        if (string.Equals(
                outputName,
                Path.GetFileName(sourcePath),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "The output name cannot match the original executable.");
        }

        return outputName;
    }

    private sealed class ClientAlreadyPatchedException(string message)
        : InvalidOperationException(message);
}
