using System;
using System.Collections.Generic;
using System.Text;
using UIKit;

using Xamarin.Forms;
using CryptText3.iOS;

[assembly: Dependency(typeof(ClipboardService))]

namespace CryptText3.iOS
{
    public class ClipboardService : IClipboardService
    {
        public void CopyToClipboard(string text)
        {
            UIPasteboard clipboard = UIPasteboard.General;
            clipboard.String = text;
        }
        public bool IsImplemented
        {
            get
            {
                return true;
            }
        }
    }
}
