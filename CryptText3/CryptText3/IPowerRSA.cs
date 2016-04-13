namespace CryptText3
{
    public interface IPowerRSA
    {
        string EncryptStringWithPublicKey(string plainText);

        string EncryptStringWithPrivateKey(string plainText);

        string DecryptStringWithPrivateKey(string cipherText);

        string DecryptStringWithPublicKey(string cipherText);

        void Dispose();

        string PublicKey { get; }

        string PrivateKey { get; }

        void ReinitializePowerRSA(string rsaKeyInfo, int keySize, PHashAlgorithm hashAlgorithm);

        void ReinitializePowerRSA(string rsaKeyInfo, int keySize);

        void ReinitializePowerRSA(int keySize);

        void ReinitializePowerRSA(int keySize, PHashAlgorithm hashAlgorithm);
    }

    public enum PHashAlgorithm
    {
        SHA1 = 0,
        SHA256 = 1,
        SHA512 = 2
    }
}