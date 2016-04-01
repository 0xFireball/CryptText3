using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Xamarin.Forms;

namespace CryptText3
{
    public partial class MainView : ContentPage
    {   
        public static IPowerAES powerAESProvider;

        public MainView()
        {
            InitializeComponent();
            powerAESProvider = DependencyService.Get<IPowerAES>();
        }

        async void OnEncrypt(object sender, EventArgs e)
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

        async void OnDecrypt(object sender, EventArgs e)
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

        async void OnCopyResult(object sender, EventArgs e)
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
