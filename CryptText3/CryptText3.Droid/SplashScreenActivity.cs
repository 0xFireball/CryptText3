using System.Threading;
using Android.App;
using Android.Content.PM;
using Android.OS;

namespace CryptText3.Droid
{
    [Activity(Theme = "@style/Theme.Splash", Label = "CryptText3", MainLauncher = true, NoHistory = true,
        ScreenOrientation = ScreenOrientation.Portrait)]
    public class SplashScreenActivity : Activity
    {
        protected override void OnCreate(Bundle savedInstanceState)
        {
            base.OnCreate(savedInstanceState);
            Thread.Sleep(1500); //Delay
            StartActivity(typeof(MainActivity));
        }
    }
}