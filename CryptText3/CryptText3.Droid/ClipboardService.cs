using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Android;
using Android.App;
using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Views;
using Android.Widget;
using Android.Preferences;

using Xamarin.Forms;
using CryptText3.Droid;

[assembly: Dependency(typeof(ClipboardService))]

namespace CryptText3.Droid
{
    public static class ContextProvider
    {
        public static Context CurrentContext;
    }
    public class ClipboardService : IClipboardService
    {
        public void CopyToClipboard(string text)
        {
            var jclipboardManager = ContextProvider.CurrentContext.GetSystemService(Context.ClipboardService);
            var clipboard = jclipboardManager.JavaCast<ClipboardManager>();
            var clip = ClipData.NewPlainText("result", text);
            clipboard.PrimaryClip = clip;
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