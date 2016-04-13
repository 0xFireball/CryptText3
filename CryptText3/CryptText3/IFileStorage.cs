namespace CryptText3
{
    public interface IFileStorage
    {
        void SaveText(string filename, string text);

        string LoadText(string filename);

        bool FileExists(string filename);
    }
}