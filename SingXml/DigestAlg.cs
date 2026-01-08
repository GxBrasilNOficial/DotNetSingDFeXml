using System.Security.Cryptography.Xml;

namespace SingXml
{
    internal enum DigestAlg
    {
        NONE, SHA1, SHA256, SHA512
    }

    internal class DigestAlgUtil
    {
        public static string GetDigest(string hash)
        {
            switch (valueOf(hash))
            {
                case DigestAlg.SHA1:
                    return SignedXml.XmlDsigSHA1Url;
                case DigestAlg.SHA256:
                    return SignedXml.XmlDsigSHA256Url;
                case DigestAlg.SHA512:
                    return SignedXml.XmlDsigSHA512Url;
                case DigestAlg.NONE:
                    return "";
                default:
                    return "";
            }
        }

        private static DigestAlg valueOf(string hash)
        {
            string cleanHash = hash.Replace("-", "");
            switch (cleanHash.ToUpper().Trim())
            {
                case "SHA1":
                    return DigestAlg.SHA1;
                case "SHA256":
                    return DigestAlg.SHA256;
                case "SHA512":
                    return DigestAlg.SHA512;
                default:
                    return DigestAlg.NONE;
            }
        }
    }

    internal class SignatureAlgUtil
    {

        public static string GetSignature(string hash)
        {
            switch (valueOf(hash))
            {
                case DigestAlg.SHA1:
                    return SignedXml.XmlDsigRSASHA1Url;
                case DigestAlg.SHA256:
                    return SignedXml.XmlDsigRSASHA256Url;
                case DigestAlg.SHA512:
                    return SignedXml.XmlDsigRSASHA512Url;
                case DigestAlg.NONE:
                    return "";
                default:
                    return "";
            }
        }

        private static DigestAlg valueOf(string hash)
        {
            string cleanHash = hash.Replace("-", "");
            switch (cleanHash.ToUpper().Trim())
            {
                case "SHA1":
                    return DigestAlg.SHA1;
                case "SHA256":
                    return DigestAlg.SHA256;
                case "SHA512":
                    return DigestAlg.SHA512;
                default:
                    return DigestAlg.NONE;
            }
        }
    }
}
