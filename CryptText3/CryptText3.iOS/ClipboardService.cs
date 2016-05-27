using CryptText3.iOS;
using UIKit;
using Xamarin.Forms;

[assembly: Dependency(typeof(ClipboardService))]

namespace CryptText3.iOS
{
    public class ClipboardService : IClipboardService
    {
        public void CopyToClipboard(string text)
        {
            var clipboard = UIPasteboard.General;
            clipboard.String = text;
        }

        public bool IsImplemented
        {
            get { return true; }
        }
    }
}