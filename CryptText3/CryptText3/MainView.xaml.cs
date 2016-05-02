using System;

using Xamarin.Forms;

namespace CryptText3
{
    public partial class MainView : TabbedPage
    {
        public static IPowerAES powerAESProvider;
        public static IPowerRSA powerRSAProvider;
        public static IFileStorage fileStorageProvider;
        public static int RSA_KEY_SIZE = 4096;

        public static string RSA_PRIKEY_FILE = "rsa.prikey";
        public static string RSA_PUBKEY_FILE = "rsa.pubkey";

        public MainView()
        {
            InitializeComponent();
            powerAESProvider = DependencyService.Get<IPowerAES>();
            powerRSAProvider = DependencyService.Get<IPowerRSA>();
            fileStorageProvider = DependencyService.Get<IFileStorage>();
            InitializeCrypt();
        }

        private async void InitializeCrypt()
        {
            try
            {
                bool isSavedPriKey = fileStorageProvider.FileExists(RSA_PRIKEY_FILE);
                if (isSavedPriKey)
                {
                    string keyInfo = fileStorageProvider.LoadText(RSA_PRIKEY_FILE);
                    powerRSAProvider.ReinitializePowerRSA(keyInfo, RSA_KEY_SIZE);
                }
            }
            catch (Exception ex)
            {
                await this.DisplayAlert(
                    "An error occurred. Please report this to the developer, and reset your keys, as they are likely corrupted. ", ex.Message, "OK");
            }
        }

        private async void OnEncrypt(object sender, EventArgs e)
        {
            try
            {
                string plaintext = rndText.Text;
                string key = keyText.Text;
                string ciphertext = powerAESProvider.Encrypt(plaintext, key);
                resultText.Text = ciphertext;
            }
            catch (PowerCryptException pcX)
            {
                await this.DisplayAlert(
                    "Cryptographic Error", pcX.Message, "OK");
            }
        }

        private async void OnDecrypt(object sender, EventArgs e)
        {
            try
            {
                string ciphertext = rndText.Text;
                string key = keyText.Text;
                string plaintext = powerAESProvider.Decrypt(ciphertext, key);
                resultText.Text = plaintext;
            }
            catch (PowerCryptException pcX)
            {
                await this.DisplayAlert(
                    "Cryptographic Error", pcX.Message, "OK");
            }
        }

        private async void OnGenerateKey(object sender, EventArgs e)
        {
            try
            {
                var answer = await this.DisplayAlert("Warning!", "Generating a new RSA key pair will overwrite the old one, and you will lose your ability to decrypt messages encrypted with those keys! Are you sure you want to continue?", "Cancel", "I'm sure");
                if (answer)
                {
                    generateKeyPairButton.IsEnabled = false;
                    generateKeyPairButton.Text = "Generating Keys...";

                    generateKeyPairButton.Text = "Generate Key Pair";
                    generateKeyPairButton.IsEnabled = true;
                }
            }
            catch (PowerCryptException pcX)
            {
                await this.DisplayAlert(
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
                clipboardProvider.CopyToClipboard(resultText.Text);
            else
                await this.DisplayAlert(
                    "Notice", "Sorry, clipboard has not yet been implemented on this platform.", "OK");
        }
    }
}