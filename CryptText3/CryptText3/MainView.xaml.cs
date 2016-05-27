using System;
using Acr.UserDialogs;
using Xamarin.Forms;

namespace CryptText3
{
    public partial class MainView : TabbedPage
    {
        public static IPowerAES PowerAESProvider;
        public static IPowerRSA PowerRSAProvider;
        public static IFileStorage FileStorageProvider;
        public static int RSAKeySize = 4096;

        public static string RSAPrikeyFile = "rsa.prikey";
        public static string RSAPubkeyFile = "rsa.pubkey";

        public MainView()
        {
            InitializeComponent();
            PowerAESProvider = DependencyService.Get<IPowerAES>();
            PowerRSAProvider = DependencyService.Get<IPowerRSA>();
            FileStorageProvider = DependencyService.Get<IFileStorage>();
            InitializeCrypt();
        }

        private async void InitializeCrypt()
        {
            try
            {
                var isSavedPriKey = FileStorageProvider.FileExists(RSAPrikeyFile);
                if (isSavedPriKey)
                {
                    var keyInfo = FileStorageProvider.LoadText(RSAPrikeyFile);
                    PowerRSAProvider.ReinitializePowerRSA(keyInfo, RSAKeySize);
                }
            }
            catch (Exception ex)
            {
                await DisplayAlert(
                    "An error occurred. Please report this to the developer, and reset your keys, as they are likely corrupted. ",
                    ex.Message, "OK");
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
                            "Cancel", "I'm sure");
                if (answer)
                {
                    GenerateKeyPairButton.IsEnabled = false;

                    var pwResult = await UserDialogs.Instance.PromptAsync("Please enter a passphrase to encrypt your key pair", "Password", inputType: InputType.Password);
                    var keyEncryptPassphrase = pwResult.Text;

                    GenerateKeyPairButton.Text = "Generating Keys...";

                    PowerRSAProvider.ReinitializePowerRSA(4096);
                    var encryptedRsaInfo = PowerAESProvider.Encrypt(keyEncryptPassphrase, PowerRSAProvider.PrivateKey);
                    FileStorageProvider.SaveText("rsainfo", encryptedRsaInfo); //Save the encrypted RSA info

                    GenerateKeyPairButton.Text = "Generate Key Pair";
                    GenerateKeyPairButton.IsEnabled = true;
                }
            }
            catch (PowerCryptException pcX)
            {
                await DisplayAlert(
                    "Cryptographic Error", pcX.Message, "OK");
            }
        }

        private async void OnPrivateKeyEncrypt(object sender, EventArgs e)
        {
        }

        private async void OnPublicKeyEncrypt(object sender, EventArgs e)
        {
        }

        private async void OnCopyRSAResult(object sender, EventArgs e)
        {
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