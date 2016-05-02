using Xamarin.Forms;

namespace CryptText3
{
    public class App : Application
    {
        #region Public Constructors

        public App()
        {
            // The root page of your application
            MainPage = new MainView();
        }

        #endregion Public Constructors

        #region Protected Methods

        protected override void OnResume()
        {
            // Handle when your app resumes
        }

        protected override void OnSleep()
        {
            // Handle when your app sleeps
        }

        protected override void OnStart()
        {
            // Handle when your app starts
        }

        #endregion Protected Methods
    }
}