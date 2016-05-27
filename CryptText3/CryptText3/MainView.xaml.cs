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
                var isSavedPriKey = fileStorageProvider.FileExists(RSA_PRIKEY_FILE);
                if (isSavedPriKey)
                {
                    var keyInfo = fileStorageProvider.LoadText(RSA_PRIKEY_FILE);
                    powerRSAProvider.ReinitializePowerRSA(keyInfo, RSA_KEY_SIZE);
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
                var ciphertext = powerAESProvider.Encrypt(plaintext, key);
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
                var plaintext = powerAESProvider.Decrypt(ciphertext, key);
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
                    GenerateKeyPairButton.Text = "Generating Keys...";

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