using System;
using Xamarin.Forms.Platform.iOS;
using Xamarin.Forms;
using UIKit;
using CoreGraphics;

using Xamarin.Forms.Utilities;
using CryptText3.iOS;

[assembly: ExportRenderer(typeof(DoneEntry), typeof(DoneEntryRenderer))]
namespace CryptText3.iOS
{
    public class DoneEntryRenderer : EntryRenderer
    {
        protected override void OnElementChanged(ElementChangedEventArgs<Entry> e)
        {
            base.OnElementChanged(e);

            var toolbar = new UIToolbar(new CGRect(0.0f, 0.0f, Control.Frame.Size.Width, 44.0f));

            toolbar.Items = new[]
            {
                new UIBarButtonItem(UIBarButtonSystemItem.FlexibleSpace),
                new UIBarButtonItem(UIBarButtonSystemItem.Done, delegate { Control.ResignFirstResponder(); })
            };

            this.Control.InputAccessoryView = toolbar;
        }
    }
}
