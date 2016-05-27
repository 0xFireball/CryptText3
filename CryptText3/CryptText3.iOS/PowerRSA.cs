using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using CryptText3.iOS;
using Xamarin.Forms;

[assembly: Dependency(typeof(PowerRSA))]

namespace CryptText3.iOS
{
    public class PowerRSA : IPowerRSA
    {
        private RSACryptoServiceProvider csp;
        private int KeySize;
        private RSAProvider rsaProvider;

        /// <summary>
        ///     Disposes the cryptographic service provider and keeps it from persisting in the CSP Container.
        /// </summary>
        public void Dispose()
        {
            csp.PersistKeyInCsp = false;
        }

        public string PublicKey
        {
            get { return csp.ToXmlString(false); }
        }

        public string PrivateKey
        {
            get { return csp.ToXmlString(true); }
        }

        public string EncryptStringWithPublicKey(string plainText)
        {
            var CTX = rsaProvider.Encrypt(Encoding.UTF8.GetBytes(plainText), false, true);
            var CipherText = Convert.ToBase64String(CTX);
            return CipherText;
        }

        public string EncryptStringWithPrivateKey(string plainText)
        {
            var CTX = rsaProvider.Encrypt(Encoding.UTF8.GetBytes(plainText), true, true);
            var CipherText = Convert.ToBase64String(CTX);
            return CipherText;
        }

        public string DecryptStringWithPrivateKey(string cipherText)
        {
            var CTX = Convert.FromBase64String(cipherText);
            var PTX = rsaProvider.Decrypt(CTX, true, true);
            var DecryptedString = Encoding.UTF8.GetString(PTX);
            return DecryptedString;
        }

        public string DecryptStringWithPublicKey(string cipherText)
        {
            var CTX = Convert.FromBase64String(cipherText);
            var PTX = rsaProvider.Decrypt(CTX, false, true);
            var DecryptedString = Encoding.UTF8.GetString(PTX);
            return DecryptedString;
        }

        private void InitRSA(int keySize, PHashAlgorithm hashAlgorithm)
        {
            KeySize = keySize;
            var keyLength = keySize;
            csp = new RSACryptoServiceProvider(keyLength);
            var rsaKeyInfo = csp.ToXmlString(true); //.Replace("><", ">\r\n<");
            rsaProvider = new RSAProvider(rsaKeyInfo, keyLength);
            switch ((int) hashAlgorithm)
            {
                case 0:
                    rsaProvider.RSAProviderHashAlgorithm = RSAProviderParameters.RSAProviderHashAlgorithm.SHA1;
                    break;

                case 1:
                    rsaProvider.RSAProviderHashAlgorithm = RSAProviderParameters.RSAProviderHashAlgorithm.SHA256;
                    break;

                case 2:
                    rsaProvider.RSAProviderHashAlgorithm = RSAProviderParameters.RSAProviderHashAlgorithm.SHA512;
                    break;
            }
        }

        #region Alternate Constructors

        public void ReinitializePowerRSA(string rsaKeyInfo, int keySize)
        {
            KeySize = keySize;
            var keyLength = keySize;
            csp = new RSACryptoServiceProvider(keyLength);
            csp.FromXmlString(rsaKeyInfo);
            rsaProvider = new RSAProvider(rsaKeyInfo, keyLength);
            rsaProvider.RSAProviderHashAlgorithm = RSAProviderParameters.RSAProviderHashAlgorithm.SHA256;
        }

        public void ReinitializePowerRSA(string rsaKeyInfo, int keySize, PHashAlgorithm hashAlgorithm)
        {
            KeySize = keySize;
            var keyLength = keySize;
            csp = new RSACryptoServiceProvider(keyLength);
            csp.FromXmlString(rsaKeyInfo);
            rsaProvider = new RSAProvider(rsaKeyInfo, keyLength);
            switch ((int) hashAlgorithm)
            {
                case 0:
                    rsaProvider.RSAProviderHashAlgorithm = RSAProviderParameters.RSAProviderHashAlgorithm.SHA1;
                    break;

                case 1:
                    rsaProvider.RSAProviderHashAlgorithm = RSAProviderParameters.RSAProviderHashAlgorithm.SHA256;
                    break;

                case 2:
                    rsaProvider.RSAProviderHashAlgorithm = RSAProviderParameters.RSAProviderHashAlgorithm.SHA512;
                    break;
            }
        }

        public void ReinitializePowerRSA(int keySize)
        {
            var ha = PHashAlgorithm.SHA256;
            InitRSA(keySize, ha);
        }

        public void ReinitializePowerRSA(int keySize, PHashAlgorithm hashAlgorithm)
        {
            InitRSA(keySize, hashAlgorithm);
        }

        #endregion Alternate Constructors
    }

    /// <summary>
    ///     Utility class for RSAProvider
    /// </summary>
    public class RSAProviderUtils
    {
        /// <summary>
        ///     Creates a RSAProviderParameters class from a given XMLKeyInfo string.
        /// </summary>
        /// <param name="XMLKeyInfo">Key Data.</param>
        /// <param name="ModulusSize">RSA Modulus Size</param>
        /// <returns>RSAProviderParameters class</returns>
        public static RSAProviderParameters GetRSAProviderParameters(string XMLKeyInfo, int ModulusSize)
        {
            var Has_CRT_Info = false;
            var Has_PRIVATE_Info = false;
            var Has_PUBLIC_Info = false;

            var doc = new XmlDocument();
            try
            {
                doc.LoadXml(XMLKeyInfo);
            }
            catch (Exception ex)
            {
                throw new Exception("Malformed KeyInfo XML: " + ex.Message);
            }

            var Modulus = new byte[0];
            var Exponent = new byte[0];
            var D = new byte[0];
            var P = new byte[0];
            var Q = new byte[0];
            var DP = new byte[0];
            var DQ = new byte[0];
            var InverseQ = new byte[0];

            try
            {
                Modulus = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("Modulus").InnerText);
                Exponent = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("Exponent").InnerText);
                Has_PUBLIC_Info = true;
            }
            catch
            {
            }

            try
            {
                Modulus = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("Modulus").InnerText);
                D = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("D").InnerText);
                Exponent = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("Exponent").InnerText);
                Has_PRIVATE_Info = true;
            }
            catch
            {
            }

            try
            {
                Modulus = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("Modulus").InnerText);
                P = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("P").InnerText);
                Q = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("Q").InnerText);
                DP = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("DP").InnerText);
                DQ = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("DQ").InnerText);
                InverseQ = Convert.FromBase64String(doc.DocumentElement.SelectSingleNode("InverseQ").InnerText);
                Has_CRT_Info = true;
            }
            catch
            {
            }

            if (Has_CRT_Info && Has_PRIVATE_Info)
            {
                return new RSAProviderParameters(Modulus, Exponent, D, P, Q, DP, DQ, InverseQ, ModulusSize);
            }
            if (Has_PRIVATE_Info)
            {
                return new RSAProviderParameters(Modulus, Exponent, D, ModulusSize);
            }
            if (Has_PUBLIC_Info)
            {
                return new RSAProviderParameters(Modulus, Exponent, ModulusSize);
            }

            throw new Exception("Could not process XMLKeyInfo. Incomplete key information.");
        }

        /// <summary>
        ///     Converts a non-negative integer to an octet string of a specified length.
        /// </summary>
        /// <param name="x">The integer to convert.</param>
        /// <param name="xLen">Length of output octets.</param>
        /// <param name="makeLittleEndian">If True little-endian converntion is followed, big-endian otherwise.</param>
        /// <returns></returns>
        public static byte[] I2OSP(BigInteger x, int xLen, bool makeLittleEndian)
        {
            var result = new byte[xLen];
            var index = 0;
            while ((x > 0) && (index < result.Length))
            {
                result[index++] = (byte) (x%256);
                x /= 256;
            }
            if (!makeLittleEndian)
                Array.Reverse(result);
            return result;
        }

        /// <summary>
        ///     Converts a byte array to a non-negative integer.
        /// </summary>
        /// <param name="data">The number in the form of a byte array.</param>
        /// <param name="isLittleEndian">Endianness of the byte array.</param>
        /// <returns>An non-negative integer from the byte array of the specified endianness.</returns>
        public static BigInteger OS2IP(byte[] data, bool isLittleEndian)
        {
            BigInteger bi = 0;
            if (isLittleEndian)
            {
                for (var i = 0; i < data.Length; i++)
                {
                    bi += BigInteger.Pow(256, i)*data[i];
                }
            }
            else
            {
                for (var i = 1; i <= data.Length; i++)
                {
                    bi += BigInteger.Pow(256, i - 1)*data[data.Length - i];
                }
            }
            return bi;
        }

        /// <summary>
        ///     Performs Bitwise Ex-OR operation to two given byte arrays.
        /// </summary>
        /// <param name="A">The first byte array.</param>
        /// <param name="B">The second byte array.</param>
        /// <returns>The bitwise Ex-OR result.</returns>
        public static byte[] XOR(byte[] A, byte[] B)
        {
            if (A.Length != B.Length)
            {
                throw new ArgumentException("XOR: Parameter length mismatch");
            }
            var R = new byte[A.Length];

            for (var i = 0; i < A.Length; i++)
            {
                R[i] = (byte) (A[i] ^ B[i]);
            }
            return R;
        }

        internal static void FixByteArraySign(ref byte[] bytes)
        {
            if ((bytes[bytes.Length - 1] & 0x80) > 0)
            {
                var temp = new byte[bytes.Length];
                Array.Copy(bytes, temp, bytes.Length);
                bytes = new byte[temp.Length + 1];
                Array.Copy(temp, bytes, temp.Length);
            }
        }
    }

    /// <summary>
    ///     Class to keep the basic RSA parameters like Keys, and other information.
    /// </summary>
    public class RSAProviderParameters : IDisposable
    {
        public enum RSAProviderHashAlgorithm
        {
            SHA1,
            SHA256,
            SHA512,
            UNDEFINED
        }

        private HashAlgorithm ha = SHA1.Create();

        /// <summary>
        ///     Initialize the RSA class. It's assumed that both the Public and Extended Private info are there.
        /// </summary>
        /// <param name="rsaParams">Preallocated RSAParameters containing the required keys.</param>
        /// <param name="ModulusSize">Modulus size in bits</param>
        public RSAProviderParameters(RSAParameters rsaParams, int ModulusSize)
        {
            // rsaParams;
            OctetsInModulus = ModulusSize/8;
            E = RSAProviderUtils.OS2IP(rsaParams.Exponent, false);
            D = RSAProviderUtils.OS2IP(rsaParams.D, false);
            N = RSAProviderUtils.OS2IP(rsaParams.Modulus, false);
            P = RSAProviderUtils.OS2IP(rsaParams.P, false);
            Q = RSAProviderUtils.OS2IP(rsaParams.Q, false);
            DP = RSAProviderUtils.OS2IP(rsaParams.DP, false);
            DQ = RSAProviderUtils.OS2IP(rsaParams.DQ, false);
            InverseQ = RSAProviderUtils.OS2IP(rsaParams.InverseQ, false);
            HasCRTInfo = true;
            Has_PUBLIC_Info = true;
            Has_PRIVATE_Info = true;
        }

        /// <summary>
        ///     Initialize the RSA class. Only the public parameters.
        /// </summary>
        /// <param name="Modulus">Modulus of the RSA key.</param>
        /// <param name="Exponent">Exponent of the RSA key</param>
        /// <param name="ModulusSize">Modulus size in number of bits. Ex: 512, 1024, 2048, 4096 etc.</param>
        public RSAProviderParameters(byte[] Modulus, byte[] Exponent, int ModulusSize)
        {
            // rsaParams;
            OctetsInModulus = ModulusSize/8;
            E = RSAProviderUtils.OS2IP(Exponent, false);
            N = RSAProviderUtils.OS2IP(Modulus, false);
            Has_PUBLIC_Info = true;
        }

        /// <summary>
        ///     Initialize the RSA class.
        /// </summary>
        /// <param name="Modulus">Modulus of the RSA key.</param>
        /// <param name="Exponent">Exponent of the RSA key</param>
        /// ///
        /// <param name="D">Exponent of the RSA key</param>
        /// <param name="ModulusSize">Modulus size in number of bits. Ex: 512, 1024, 2048, 4096 etc.</param>
        public RSAProviderParameters(byte[] Modulus, byte[] Exponent, byte[] D, int ModulusSize)
        {
            // rsaParams;
            OctetsInModulus = ModulusSize/8;
            E = RSAProviderUtils.OS2IP(Exponent, false);
            N = RSAProviderUtils.OS2IP(Modulus, false);
            this.D = RSAProviderUtils.OS2IP(D, false);
            Has_PUBLIC_Info = true;
            Has_PRIVATE_Info = true;
        }

        /// <summary>
        ///     Initialize the RSA class. For CRT.
        /// </summary>
        /// <param name="Modulus">Modulus of the RSA key.</param>
        /// <param name="Exponent">Exponent of the RSA key</param>
        /// ///
        /// <param name="D">Exponent of the RSA key</param>
        /// <param name="P">P paramater of RSA Algorithm.</param>
        /// <param name="Q">Q paramater of RSA Algorithm.</param>
        /// <param name="DP">DP paramater of RSA Algorithm.</param>
        /// <param name="DQ">DQ paramater of RSA Algorithm.</param>
        /// <param name="InverseQ">InverseQ paramater of RSA Algorithm.</param>
        /// <param name="ModulusSize">Modulus size in number of bits. Ex: 512, 1024, 2048, 4096 etc.</param>
        public RSAProviderParameters(byte[] Modulus, byte[] Exponent, byte[] D, byte[] P, byte[] Q, byte[] DP, byte[] DQ,
            byte[] InverseQ, int ModulusSize)
        {
            // rsaParams;
            OctetsInModulus = ModulusSize/8;
            E = RSAProviderUtils.OS2IP(Exponent, false);
            N = RSAProviderUtils.OS2IP(Modulus, false);
            this.D = RSAProviderUtils.OS2IP(D, false);
            this.P = RSAProviderUtils.OS2IP(P, false);
            this.Q = RSAProviderUtils.OS2IP(Q, false);
            this.DP = RSAProviderUtils.OS2IP(DP, false);
            this.DQ = RSAProviderUtils.OS2IP(DQ, false);
            this.InverseQ = RSAProviderUtils.OS2IP(InverseQ, false);
            HasCRTInfo = true;
            Has_PUBLIC_Info = true;
            Has_PRIVATE_Info = true;
        }

        /// <summary>
        ///     Gets and sets the HashAlgorithm for RSA-OAEP padding.
        /// </summary>
        public RSAProviderHashAlgorithm HashAlgorithm
        {
            get
            {
                var al = RSAProviderHashAlgorithm.UNDEFINED;
                switch (ha.GetType().ToString())
                {
                    case "SHA1":
                        al = RSAProviderHashAlgorithm.SHA1;
                        break;

                    case "SHA256":
                        al = RSAProviderHashAlgorithm.SHA256;
                        break;

                    case "SHA512":
                        al = RSAProviderHashAlgorithm.SHA512;
                        break;
                }
                return al;
            }

            set
            {
                switch (value)
                {
                    case RSAProviderHashAlgorithm.SHA1:
                        ha = SHA1.Create();
                        hLen = 20;
                        break;

                    case RSAProviderHashAlgorithm.SHA256:
                        ha = SHA256.Create();
                        hLen = 32;
                        break;

                    case RSAProviderHashAlgorithm.SHA512:
                        ha = SHA512.Create();
                        hLen = 64;
                        break;
                }
            }
        }

        public bool HasCRTInfo { get; }

        public bool Has_PRIVATE_Info { get; }

        public bool Has_PUBLIC_Info { get; }

        public int OctetsInModulus { get; }

        public BigInteger N { get; }

        public int hLen { get; private set; } = 20;

        public BigInteger P { get; }

        public BigInteger Q { get; }

        public BigInteger DP { get; }

        public BigInteger DQ { get; }

        public BigInteger InverseQ { get; }

        public BigInteger E { get; }

        public BigInteger D { get; }

        public void Dispose()
        {
            ha.Dispose();
        }

        /// <summary>
        ///     Computes the hash from the given data.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>Hash of the data.</returns>
        public byte[] ComputeHash(byte[] data)
        {
            return ha.ComputeHash(data);
        }
    }

    /// <summary>
    ///     The main RSAProvider Class
    /// </summary>
    public class RSAProvider : IDisposable
    {
        private readonly RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        private readonly RSAProviderParameters rsaParams;

        /// <summary>
        ///     Initialize the RSA class.
        /// </summary>
        /// <param name="rsaParams">Preallocated RSAProviderParameters containing the required keys.</param>
        public RSAProvider(RSAProviderParameters rsaParams)
        {
            this.rsaParams = rsaParams;
            UseCRTForPublicDecryption = true;
        }

        /// <summary>
        ///     Initialize the RSA class from a XML KeyInfo string.
        /// </summary>
        /// <param name="keyInfo">XML Containing Key Information</param>
        /// <param name="ModulusSize">Length of RSA Modulus in bits.</param>
        public RSAProvider(string keyInfo, int ModulusSize)
        {
            rsaParams = RSAProviderUtils.GetRSAProviderParameters(keyInfo, ModulusSize);
            UseCRTForPublicDecryption = true;
        }

        /// <summary>
        ///     Hash Algorithm to be used for OAEP encoding.
        /// </summary>
        public RSAProviderParameters.RSAProviderHashAlgorithm RSAProviderHashAlgorithm
        {
            set { rsaParams.HashAlgorithm = value; }
        }

        /// <summary>
        ///     If True, and if the parameters are available, uses CRT for private key decryption. (Much Faster)
        /// </summary>
        public bool UseCRTForPublicDecryption { get; set; }

        /// <summary>
        ///     Releases all the resources.
        /// </summary>
        public void Dispose()
        {
            rsaParams.Dispose();
        }

        #region PRIVATE FUNCTIONS

        /// <summary>
        ///     Low level RSA Process function for use with private key.
        ///     Should never be used; Because without padding RSA is vulnerable to attacks.  Use with caution.
        /// </summary>
        /// <param name="PlainText">Data to encrypt. Length must be less than Modulus size in octets.</param>
        /// <param name="usePrivate">True to use Private key, else Public.</param>
        /// <returns>Encrypted Data</returns>
        public byte[] RSAProcess(byte[] PlainText, bool usePrivate)
        {
            if (usePrivate && !rsaParams.Has_PRIVATE_Info)
            {
                throw new PowerCryptException("RSA Process: Incomplete Private Key Info");
            }

            if ((usePrivate == false) && !rsaParams.Has_PUBLIC_Info)
            {
                throw new PowerCryptException("RSA Process: Incomplete Public Key Info");
            }

            BigInteger _E;
            if (usePrivate)
                _E = rsaParams.D;
            else
                _E = rsaParams.E;

            var PT = RSAProviderUtils.OS2IP(PlainText, false);
            var M = BigInteger.ModPow(PT, _E, rsaParams.N);

            if (M.Sign == -1)
                return RSAProviderUtils.I2OSP(M + rsaParams.N, rsaParams.OctetsInModulus, false);
            return RSAProviderUtils.I2OSP(M, rsaParams.OctetsInModulus, false);
        }

        /// <summary>
        ///     Low level RSA Decryption function for use with private key. Uses CRT and is Much faster.
        ///     Should never be used; Because without padding RSA is vulnerable to attacks. Use with caution.
        /// </summary>
        /// <param name="Data">Data to encrypt. Length must be less than Modulus size in octets.</param>
        /// <returns>Encrypted Data</returns>
        public byte[] RSADecryptPrivateCRT(byte[] Data)
        {
            if (rsaParams.Has_PRIVATE_Info && rsaParams.HasCRTInfo)
            {
                var C = RSAProviderUtils.OS2IP(Data, false);

                var M1 = BigInteger.ModPow(C, rsaParams.DP, rsaParams.P);
                var M2 = BigInteger.ModPow(C, rsaParams.DQ, rsaParams.Q);
                var H = (M1 - M2)*rsaParams.InverseQ%rsaParams.P;
                var M = M2 + rsaParams.Q*H;

                if (M.Sign == -1)
                    return RSAProviderUtils.I2OSP(M + rsaParams.N, rsaParams.OctetsInModulus, false);
                return RSAProviderUtils.I2OSP(M, rsaParams.OctetsInModulus, false);
            }
            throw new PowerCryptException("RSA Decrypt CRT: Incomplete Key Info");
        }

        private byte[] RSAProcessEncodePKCS(byte[] Message, bool usePrivate)
        {
            if (Message.Length > rsaParams.OctetsInModulus - 11)
            {
                throw new ArgumentException("Message too long.");
            }
            // RFC3447 : Page 24. [RSAES-PKCS1-V1_5-ENCRYPT ((n, e), M)]
            // EM = 0x00 || 0x02 || PS || 0x00 || Msg

            var PCKSv15_Msg = new List<byte>();

            PCKSv15_Msg.Add(0x00);
            PCKSv15_Msg.Add(0x02);

            var PaddingLength = rsaParams.OctetsInModulus - Message.Length - 3;

            var PS = new byte[PaddingLength];
            rng.GetNonZeroBytes(PS);

            PCKSv15_Msg.AddRange(PS);
            PCKSv15_Msg.Add(0x00);

            PCKSv15_Msg.AddRange(Message);

            return RSAProcess(PCKSv15_Msg.ToArray(), usePrivate);
        }

        /// <summary>
        ///     Mask Generation Function
        /// </summary>
        /// <param name="Z">Initial pseudorandom Seed.</param>
        /// <param name="l">Length of output required.</param>
        /// <returns></returns>
        private byte[] MGF(byte[] Z, int l)
        {
            if (l > Math.Pow(2, 32))
            {
                throw new ArgumentException("Mask too long.");
            }
            var result = new List<byte>();
            for (var i = 0; i <= l/rsaParams.hLen; i++)
            {
                var data = new List<byte>();
                data.AddRange(Z);
                data.AddRange(RSAProviderUtils.I2OSP(i, 4, false));
                result.AddRange(rsaParams.ComputeHash(data.ToArray()));
            }

            if (l <= result.Count)
            {
                return result.GetRange(0, l).ToArray();
            }
            throw new ArgumentException("Invalid Mask Length.");
        }

        private byte[] RSAProcessEncodeOAEP(byte[] M, byte[] P, bool usePrivate)
        {
            //                           +----------+---------+-------+
            //                      DB = |  lHash   |    PS   |   M   |
            //                           +----------+---------+-------+
            //                                          |
            //                +----------+              V
            //                |   seed   |--> MGF ---> XOR
            //                +----------+              |
            //                      |                   |
            //             +--+     V                   |
            //             |00|    XOR <----- MGF <-----|
            //             +--+     |                   |
            //               |      |                   |
            //               V      V                   V
            //             +--+----------+----------------------------+
            //       EM =  |00|maskedSeed|          maskedDB          |
            //             +--+----------+----------------------------+

            var mLen = M.Length;
            if (mLen > rsaParams.OctetsInModulus - 2*rsaParams.hLen - 2)
            {
                throw new ArgumentException("Message too long.");
            }
            var PS = new byte[rsaParams.OctetsInModulus - mLen - 2*rsaParams.hLen - 2];
            //4. pHash = Hash(P),
            var pHash = rsaParams.ComputeHash(P);

            //5. DB = pHash||PS||01||M.
            var _DB = new List<byte>();
            _DB.AddRange(pHash);
            _DB.AddRange(PS);
            _DB.Add(0x01);
            _DB.AddRange(M);
            var DB = _DB.ToArray();

            //6. Generate a random octet string seed of length hLen.
            var seed = new byte[rsaParams.hLen];
            rng.GetBytes(seed);

            //7. dbMask = MGF(seed, k - hLen -1).
            var dbMask = MGF(seed, rsaParams.OctetsInModulus - rsaParams.hLen - 1);

            //8. maskedDB = DB XOR dbMask
            var maskedDB = RSAProviderUtils.XOR(DB, dbMask);

            //9. seedMask = MGF(maskedDB, hLen)
            var seedMask = MGF(maskedDB, rsaParams.hLen);

            //10. maskedSeed = seed XOR seedMask.
            var maskedSeed = RSAProviderUtils.XOR(seed, seedMask);

            //11. EM = 0x00 || maskedSeed || maskedDB.
            var result = new List<byte>();
            result.Add(0x00);
            result.AddRange(maskedSeed);
            result.AddRange(maskedDB);

            return RSAProcess(result.ToArray(), usePrivate);
        }

        private byte[] Decrypt(byte[] Message, byte[] Parameters, bool usePrivate, bool fOAEP)
        {
            var EM = new byte[0];
            try
            {
                if (usePrivate && UseCRTForPublicDecryption && rsaParams.HasCRTInfo)
                {
                    EM = RSADecryptPrivateCRT(Message);
                }
                else
                {
                    EM = RSAProcess(Message, usePrivate);
                }
            }
            catch (PowerCryptException ex)
            {
                throw new PowerCryptException("Exception while Decryption: " + ex.Message);
            }
            catch
            {
                throw new Exception("Exception while Decryption: ");
            }

            try
            {
                if (fOAEP) //DECODE OAEP
                {
                    if ((EM.Length == rsaParams.OctetsInModulus) && (EM.Length > 2*rsaParams.hLen + 1))
                    {
                        byte[] maskedSeed;
                        byte[] maskedDB;
                        var pHash = rsaParams.ComputeHash(Parameters);
                        if (EM[0] == 0) // RFC3447 Format : http://tools.ietf.org/html/rfc3447
                        {
                            maskedSeed = EM.ToList().GetRange(1, rsaParams.hLen).ToArray();
                            maskedDB =
                                EM.ToList().GetRange(1 + rsaParams.hLen, EM.Length - rsaParams.hLen - 1).ToArray();
                            var seedMask = MGF(maskedDB, rsaParams.hLen);
                            var seed = RSAProviderUtils.XOR(maskedSeed, seedMask);
                            var dbMask = MGF(seed, rsaParams.OctetsInModulus - rsaParams.hLen - 1);
                            var DB = RSAProviderUtils.XOR(maskedDB, dbMask);

                            if (DB.Length >= rsaParams.hLen + 1)
                            {
                                var _pHash = DB.ToList().GetRange(0, rsaParams.hLen).ToArray();
                                var PS_M = DB.ToList().GetRange(rsaParams.hLen, DB.Length - rsaParams.hLen);
                                var pos = PS_M.IndexOf(0x01);
                                if (pos >= 0 && (pos < PS_M.Count))
                                {
                                    var _01_M = PS_M.GetRange(pos, PS_M.Count - pos);
                                    byte[] M;
                                    if (_01_M.Count > 1)
                                    {
                                        M = _01_M.GetRange(1, _01_M.Count - 1).ToArray();
                                    }
                                    else
                                    {
                                        M = new byte[0];
                                    }
                                    var success = true;
                                    for (var i = 0; i < rsaParams.hLen; i++)
                                    {
                                        if (_pHash[i] != pHash[i])
                                        {
                                            success = false;
                                            break;
                                        }
                                    }

                                    if (success)
                                    {
                                        return M;
                                    }
                                    M = new byte[rsaParams.OctetsInModulus]; //Hash Match Failure.
                                    throw new PowerCryptException("OAEP Decode Error");
                                }
                                // #3: Invalid Encoded Message Length.
                                throw new PowerCryptException("OAEP Decode Error");
                            }
                            // #2: Invalid Encoded Message Length.
                            throw new PowerCryptException("OAEP Decode Error");
                        }
                        //OAEP : THIS STADNARD IS NOT IMPLEMENTED
                        throw new PowerCryptException("OAEP Decode Error");
                    }
                    // #1: Invalid Encoded Message Length.
                    throw new PowerCryptException("OAEP Decode Error");
                }
                if (EM.Length >= 11)
                {
                    if ((EM[0] == 0x00) && (EM[1] == 0x02))
                    {
                        var startIndex = 2;
                        var PS = new List<byte>();
                        for (var i = startIndex; i < EM.Length; i++)
                        {
                            if (EM[i] != 0)
                            {
                                PS.Add(EM[i]);
                            }
                            else
                            {
                                break;
                            }
                        }

                        if (PS.Count >= 8)
                        {
                            var DecodedDataIndex = startIndex + PS.Count + 1;
                            if (DecodedDataIndex < EM.Length - 1)
                            {
                                var DATA = new List<byte>();
                                for (var i = DecodedDataIndex; i < EM.Length; i++)
                                {
                                    DATA.Add(EM[i]);
                                }
                                return DATA.ToArray();
                            }
                            return new byte[0];
                            //throw new PowerCryptException("PKCS v1.5 Decode Error #4: No Data");
                        }
                        // #3: Invalid Key / Invalid Random Data Length
                        throw new PowerCryptException("PKCS v1.5 Decode Error");
                    }
                    // #2: Invalid Key / Invalid Identifiers
                    throw new PowerCryptException("PKCS v1.5 Decode Error");
                }
                // #1: Invalid Key / PKCS Encoding
                throw new PowerCryptException("PKCS v1.5 Decode Error");
            }
            catch (PowerCryptException ex)
            {
                throw new PowerCryptException("Exception while decoding: " + ex.Message);
            }
            catch
            {
                throw new PowerCryptException("Exception while decoding");
            }
        }

        #endregion PRIVATE FUNCTIONS

        #region PUBLIC FUNCTIONS

        /// <summary>
        ///     Encrypts the given message with RSA, performs OAEP Encoding.
        /// </summary>
        /// <param name="Message">
        ///     Message to Encrypt. Maximum message length is (ModulusLengthInOctets - 2 * HashLengthInOctets -
        ///     2)
        /// </param>
        /// <param name="OAEP_Params">Optional OAEP parameters. Normally Empty. But, must match the parameters while decryption.</param>
        /// <param name="usePrivate">True to use Private key for encryption. False to use Public key.</param>
        /// <returns>Encrypted message.</returns>
        public byte[] Encrypt(byte[] Message, byte[] OAEP_Params, bool usePrivate)
        {
            return RSAProcessEncodeOAEP(Message, OAEP_Params, usePrivate);
        }

        /// <summary>
        ///     Encrypts the given message with RSA.
        /// </summary>
        /// <param name="Message">
        ///     Message to Encrypt. Maximum message length is For OAEP [ModulusLengthInOctets - (2 *
        ///     HashLengthInOctets) - 2] and for PKCS [ModulusLengthInOctets - 11]
        /// </param>
        /// <param name="usePrivate">True to use Private key for encryption. False to use Public key.</param>
        /// <param name="fOAEP">True to use OAEP encoding (Recommended), False to use PKCS v1.5 Padding.</param>
        /// <returns>Encrypted message.</returns>
        public byte[] Encrypt(byte[] Message, bool usePrivate, bool fOAEP)
        {
            if (fOAEP)
            {
                return RSAProcessEncodeOAEP(Message, new byte[0], usePrivate);
            }
            return RSAProcessEncodePKCS(Message, usePrivate);
        }

        /// <summary>
        ///     Encrypts the given message using RSA Public Key.
        /// </summary>
        /// <param name="Message">
        ///     Message to Encrypt. Maximum message length is For OAEP [ModulusLengthInOctets - (2 *
        ///     HashLengthInOctets) - 2] and for PKCS [ModulusLengthInOctets - 11]
        /// </param>
        /// <param name="fOAEP">True to use OAEP encoding (Recommended), False to use PKCS v1.5 Padding.</param>
        /// <returns>Encrypted message.</returns>
        public byte[] Encrypt(byte[] Message, bool fOAEP)
        {
            if (fOAEP)
            {
                return RSAProcessEncodeOAEP(Message, new byte[0], false);
            }
            return RSAProcessEncodePKCS(Message, false);
        }

        /// <summary>
        ///     Decrypts the given RSA encrypted message.
        /// </summary>
        /// <param name="Message">The encrypted message.</param>
        /// <param name="usePrivate">True to use Private key for decryption. False to use Public key.</param>
        /// <param name="fOAEP">True to use OAEP.</param>
        /// <returns>Encrypted byte array.</returns>
        public byte[] Decrypt(byte[] Message, bool usePrivate, bool fOAEP)
        {
            return Decrypt(Message, new byte[0], usePrivate, fOAEP);
        }

        /// <summary>
        ///     Decrypts the given RSA encrypted message.
        /// </summary>
        /// <param name="Message">The encrypted message.</param>
        /// <param name="OAEP_Params">Parameters to the OAEP algorithm (Must match the parameter while Encryption).</param>
        /// <param name="usePrivate">True to use Private key for decryption. False to use Public key.</param>
        /// <returns>Encrypted byte array.</returns>
        public byte[] Decrypt(byte[] Message, byte[] OAEP_Params, bool usePrivate)
        {
            return Decrypt(Message, OAEP_Params, usePrivate, true);
        }

        /// <summary>
        ///     Decrypts the given RSA encrypted message using Private key.
        /// </summary>
        /// <param name="Message">The encrypted message.</param>
        /// <param name="fOAEP">True to use OAEP.</param>
        /// <returns>Encrypted byte array.</returns>
        public byte[] Decrypt(byte[] Message, bool fOAEP)
        {
            return Decrypt(Message, new byte[0], true, fOAEP);
        }

        #endregion PUBLIC FUNCTIONS
    }
}