using Microsoft.Win32;
using System.Windows;
using ConquerRsaTool.Core.Crypto;
using ConquerRsaTool.Core.Patching;

namespace ConquerRsaTool.Wpf;

public partial class MainWindow : Window
{
    private readonly RsaKeyService _keys = new();
    private readonly ConquerDatService _dat = new();
    private readonly ConquerBinaryService _binary = new();

    public MainWindow()
    {
        InitializeComponent();
        Log("Aplicación iniciada. Trabaja siempre sobre copias de seguridad.");
    }

    private async Task RunAsync(string operation, Action action)
    {
        try
        {
            IsEnabled = false;
            Log($"{operation}...");
            await Task.Run(action);
            Log($"{operation}: completado.");
        }
        catch (Exception ex)
        {
            Log($"ERROR: {ex.Message}");
            MessageBox.Show(this, ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { IsEnabled = true; }
    }

    private void Log(string message)
    {
        Dispatcher.Invoke(() => { LogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}"); LogBox.ScrollToEnd(); });
    }

    private static string? Open(string filter)
    {
        var dialog = new OpenFileDialog { Filter = filter, CheckFileExists = true };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    private static string? Save(string filter, string fileName)
    {
        var dialog = new SaveFileDialog { Filter = filter, FileName = fileName, AddExtension = true };
        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    private void BrowseExe_Click(object s, RoutedEventArgs e) { var p=Open("Ejecutable Conquer|*.exe|Todos|*.*"); if(p!=null){ExePath.Text=p; PatchedExeOutput.Text=Path.Combine(Path.GetDirectoryName(p)!,"Conquer_modified.exe");} }
    private void BrowsePatchPublicKey_Click(object s, RoutedEventArgs e) => Set(PatchPublicKeyPath, Open("Clave PEM|*.pem|Todos|*.*"));
    private void BrowsePatchedOutput_Click(object s, RoutedEventArgs e) => Set(PatchedExeOutput, Save("Ejecutable|*.exe", "Conquer_modified.exe"));
    private void BrowsePublicOutput_Click(object s, RoutedEventArgs e) => Set(PublicKeyOutput, Save("Clave PEM|*.pem", "public_key.pem"));
    private void BrowsePrivateOutput_Click(object s, RoutedEventArgs e) => Set(PrivateKeyOutput, Save("Clave PEM|*.pem", "private_key.pem"));
    private void BrowseDecryptInput_Click(object s, RoutedEventArgs e) { var p=Open("Archivos DAT|*.dat|Todos|*.*"); if(p!=null){DecryptInput.Text=p; DecryptOutput.Text=DefaultOutput(p,"_decrypted");} }
    private void BrowseDecryptKey_Click(object s, RoutedEventArgs e) => Set(DecryptPublicKey, Open("Clave PEM|*.pem|Todos|*.*"));
    private void BrowseDecryptOutput_Click(object s, RoutedEventArgs e) => Set(DecryptOutput, Save("Archivos DAT|*.dat|Todos|*.*", "decrypted.dat"));
    private void BrowseEncryptInput_Click(object s, RoutedEventArgs e) { var p=Open("Archivos DAT|*.dat|Todos|*.*"); if(p!=null){EncryptInput.Text=p; EncryptOutput.Text=DefaultOutput(p,"_encrypted");} }
    private void BrowseEncryptKey_Click(object s, RoutedEventArgs e) => Set(EncryptPrivateKey, Open("Clave PEM|*.pem|Todos|*.*"));
    private void BrowseEncryptOutput_Click(object s, RoutedEventArgs e) => Set(EncryptOutput, Save("Archivos DAT|*.dat|Todos|*.*", "encrypted.dat"));

    private async void GenerateKeys_Click(object s, RoutedEventArgs e) => await RunAsync("Generando claves", () => _keys.GenerateKeyPair(Required(PublicKeyOutput.Text,"destino público"), Required(PrivateKeyOutput.Text,"destino privado")));
    private async void Analyze_Click(object s, RoutedEventArgs e) => await RunAsync("Analizando cliente", () => { var r=_binary.Analyze(Required(ExePath.Text,"Conquer.exe")); Log($"Compatible: {(r.Supported?"sí":"no")}. {r.Message} Formato: {(r.IsContiguous?"matriz contigua":"instrucciones Windows")}"); if(!r.Supported) throw new InvalidDataException(r.Message); });
    private async void ExtractKey_Click(object s, RoutedEventArgs e)
    {
        var output=Save("Clave PEM|*.pem","extracted_public_key.pem"); if(output is null)return;
        await RunAsync("Extrayendo clave pública", () => _binary.ExtractPublicKey(Required(ExePath.Text,"Conquer.exe"),output));
    }
    private async void PatchClient_Click(object s, RoutedEventArgs e) => await RunAsync("Parcheando cliente", () => { var r=_binary.Patch(Required(ExePath.Text,"Conquer.exe"),Required(PatchPublicKeyPath.Text,"clave pública"),Required(PatchedExeOutput.Text,"destino"),BypassPlayExe.IsChecked==true); Log(r.PlayExeBypassMessage); });
    private async void Decrypt_Click(object s, RoutedEventArgs e) => await RunAsync("Descifrando archivo", () => _dat.Decrypt(Required(DecryptInput.Text,"archivo cifrado"),Required(DecryptPublicKey.Text,"clave pública"),Required(DecryptOutput.Text,"destino")));
    private async void Encrypt_Click(object s, RoutedEventArgs e) => await RunAsync("Cifrando archivo", () => _dat.Encrypt(Required(EncryptInput.Text,"archivo plano"),Required(EncryptPrivateKey.Text,"clave privada"),Required(EncryptOutput.Text,"destino")));

    private static void Set(System.Windows.Controls.TextBox box, string? value) { if(value!=null)box.Text=value; }
    private static string Required(string value, string name) => string.IsNullOrWhiteSpace(value) ? throw new InvalidOperationException($"Falta seleccionar: {name}.") : Path.GetFullPath(value);
    private static string DefaultOutput(string path,string suffix) => Path.Combine(Path.GetDirectoryName(path)!,Path.GetFileNameWithoutExtension(path)+suffix+Path.GetExtension(path));
}
