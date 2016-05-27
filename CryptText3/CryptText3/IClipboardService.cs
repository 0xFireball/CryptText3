namespace CryptText3
{
    public interface IClipboardService
    {
        bool IsImplemented { get; }
        void CopyToClipboard(string text);
    }
}