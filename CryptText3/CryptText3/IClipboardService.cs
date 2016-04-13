namespace CryptText3
{
    public interface IClipboardService
    {
        void CopyToClipboard(string text);

        bool IsImplemented { get; }
    }
}