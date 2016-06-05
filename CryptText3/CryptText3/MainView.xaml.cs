using System;
using System.Threading.Tasks;
using Acr.UserDialogs;
using Xamarin.Forms;

namespace CryptText3
{
    public partial class MainView : TabbedPage
    {
        public static IPowerAES PowerAESProvider;
        public static IPowerRSA PowerRSAProvider;
        public static IFileStorage FileStorageProvider;
        public static int RSAKeySize = 2048;
        public static bool RsaKeypairAvailable = false;

        public static string RSAPrikeyFile = "rsa.prikey";

        public MainView()
        {
            InitializeComponent();
            PowerAESProvider = DependencyService.Get<IPowerAES>();
            PowerRSAProvider = DependencyService.Get<IPowerRSA>();
            FileStorageProvider = DependencyService.Get<IFileStorage>();
            LoadRsaKeys();
        }

        private async void LoadRsaKeys()
        {
            try
            {
                var isSavedPriKey = FileStorageProvider.FileExists(RSAPrikeyFile);
                var keyAvailable = false;
                if (isSavedPriKey)
                {
                    var encryptedKeyInfo = FileStorageProvider.LoadText(RSAPrikeyFile);
                    var pwResult = await UserDialogs.Instance.PromptAsync("Please enter your passphrase to decrypt and load your key pair", "Passphrase", inputType: InputType.Password);
                    var keypairPassphrase = pwResult.Text;
                    try
                    {
                        var decryptedKeyInfo = PowerAESProvider.Decrypt(encryptedKeyInfo, keypairPassphrase);
                        PowerRSAProvider.ReinitializePowerRSA(decryptedKeyInfo, RSAKeySize);
                        keyAvailable = true;
                    }
                    catch (PowerCryptException)
                    {
                        await DisplayAlert("Decryption Error", "The saved keypair data could not be decrypted with the given passphrase.", "Dismiss");
                    }
                }
                ExistingKeyInfo.Text = keyAvailable ? "Keys loaded from storage" : "No keypair found.";
                RsaKeypairAvailable = keyAvailable;
            }
            catch (Exception ex)
            {
                await DisplayAlert("Error",
                    "The saved keypair data could not be loaded. Please ensure that your passphrase is correct.", "OK");
            }
        }

        private async void OnEncrypt(object sender, EventArgs e)
        {
            try
            {
                var plaintext = RndText.Text;
                var key = KeyText.Text;
                var ciphertext = PowerAESProvider.Encrypt(plaintext, key);
                ResultText.Text = ciphertext;
            }
            catch (PowerCryptException pcX)
            {
                await DisplayAlert(
                    "Cryptographic Error", pcX.Message, "OK");
            }
        }

        private async void OnDecrypt(object sender, EventArgs e)
        {
            try
            {
                var ciphertext = RndText.Text;
                var key = KeyText.Text;
                var plaintext = PowerAESProvider.Decrypt(ciphertext, key);
                ResultText.Text = plaintext;
            }
            catch (PowerCryptException pcX)
            {
                await DisplayAlert(
                    "Cryptographic Error", pcX.Message, "OK");
            }
        }

        private async void OnGenerateKey(object sender, EventArgs e)
        {
            try
            {
                var answer =
                    await
                        DisplayAlert("Warning!",
                            "Generating a new RSA key pair will overwrite the old one, and you will lose your ability to decrypt messages encrypted with those keys! Are you sure you want to continue?",
                            "I'm sure", "Cancel");
                if (!answer) return;
                GenerateKeyPairButton.IsEnabled = false;

                var pwResult = await UserDialogs.Instance.PromptAsync("Please enter a passphrase to encrypt your key pair", "Password", inputType: InputType.Password);
                var keyEncryptPassphrase = pwResult.Text;

                GenerateKeyPairButton.Text = "Generating Keys...";

                var progressController = UserDialogs.Instance.Progress(new ProgressDialogConfig() { AutoShow = true, IsDeterministic = false, Title = "Please wait, generating keys..." });
                progressController.Show();
                //Generate keys asynchronously, as this can be quite time consuming
                await Task.Run(() => PowerRSAProvider.ReinitializePowerRSA(RSAKeySize));
                var encryptedRsaInfo = PowerAESProvider.Encrypt(PowerRSAProvider.PrivateKey, keyEncryptPassphrase);
                FileStorageProvider.SaveText(RSAPrikeyFile, encryptedRsaInfo); //Save the encrypted RSA info
                progressController.Hide(); //Dismiss the progress thing
                GenerateKeyPairButton.Text = "Generate Key Pair";
                GenerateKeyPairButton.IsEnabled = true;
                LoadRsaKeys(); //Reload keys
            }
            catch (PowerCryptException pcX)
            {
                await DisplayAlert(
                    "Cryptographic Error", pcX.Message, "OK");
            }
        }

        private async Task<bool> EnsureKeypairAvailable()
        {
            if (!RsaKeypairAvailable)
            {
                await DisplayAlert(
                    "Keypair unavailable",
                    "Sorry, this operation is unavailable as no keypair has been loaded. Please generate one or restart the application and successfully decrypt the saved keypair.",
                    "OK");
                return false;
            }
            return true;
        }

        private async void OnPrivateKeyEncrypt(object sender, EventArgs e)
        {
            if (!await EnsureKeypairAvailable()) return;
        }

        private async void OnPublicKeyEncrypt(object sender, EventArgs e)
        {
            if (!await EnsureKeypairAvailable()) return;
        }

        private async void OnCopyRSAResult(object sender, EventArgs e)
        {
            if (!await EnsureKeypairAvailable()) return;
        }

        private async void OnCopyResult(object sender, EventArgs e)
        {
            var clipboardProvider = DependencyService.Get<IClipboardService>();
            if (clipboardProvider.IsImplemented)
                clipboardProvider.CopyToClipboard(ResultText.Text);
            else
                await DisplayAlert(
                    "Notice", "Sorry, clipboard has not yet been implemented on this platform.", "OK");
        }
    }
}