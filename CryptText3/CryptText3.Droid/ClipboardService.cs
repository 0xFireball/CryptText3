using Android.Content;
using Android.Runtime;
using CryptText3.Droid;
using Xamarin.Forms;

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