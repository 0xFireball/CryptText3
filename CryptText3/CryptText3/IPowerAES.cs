namespace CryptText3
{
    public interface IPowerAES
    {
        string Encrypt(string plaintext, string key);

        string Decrypt(string ciphertext, string key);
    }
}