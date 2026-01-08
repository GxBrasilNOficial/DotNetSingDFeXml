using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace SingXml
{
    internal class Keys
    {
        internal static AsymmetricAlgorithm LoadPrivateKey(string path, string password)
        {
            //loads a private key from a pkcs12 keystore
            Pkcs12Store pkcs12 = null;
            try
            {
                pkcs12 = new Pkcs12StoreBuilder().Build();
                using (FileStream fs = new FileStream(GetCertPath(path), FileMode.Open, FileAccess.Read))
                {
                    pkcs12.Load(fs, password.ToCharArray());
                }
            }

            catch (Exception)
            {
                return null;
            }
            string pName = null;
            foreach (string n in pkcs12.Aliases)
            {
                if (pkcs12.IsKeyEntry(n) && pkcs12.GetKey(n).Key.IsPrivate)
                {
                    pName = n;
                    PrivateKeyInfo pk = PrivateKeyInfoFactory.CreatePrivateKeyInfo(pkcs12.GetKey(n).Key);
                    return CastPrivateKey(pk);
                }

            }
            return null;


        }

        internal static X509Certificate2 LoadCertificate(string path, string pass)
        {
            return new X509Certificate2(path, pass,
                X509KeyStorageFlags.MachineKeySet |
                X509KeyStorageFlags.PersistKeySet |
                X509KeyStorageFlags.Exportable);
        }

        private static string GetCertPath(string path)
        {
            string currentDir = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory).Parent.ToString();
            return Path.IsPathRooted(path) ? path : Path.Combine(currentDir, path);
        }

        private static AsymmetricAlgorithm CastPrivateKey(PrivateKeyInfo privateKeyInfo)
        {
            byte[] serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetDerEncoded();

            // cria parâmetros RSA a partir do ASN.1
            RsaPrivateCrtKeyParameters privateKey = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(serializedPrivateBytes);

            // Em .NET Framework (net48) não existe ImportPkcs8PrivateKey, então convertemos via BouncyCastle
#if NET48 || NETFRAMEWORK
            return DotNetUtilities.ToRSA(privateKey);
#else
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
            {
                return DotNetUtilities.ToRSA(privateKey);
            }
            else
            {
                try
                {
                    RSA rsa = RSA.Create();
                    rsa.ImportPkcs8PrivateKey(serializedPrivateBytes, out int _);
                    return rsa;
                }
                catch (Exception)
                {
                    return null;
                }
            }
#endif
        }
    }
}
