using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace SingXml
{
    public class Signer
    {
        internal static string ALGO_ID_C14N_OMIT_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
        internal static string NFE_ID_ATT_NAME = "Id";
        internal static string REFERENCE_URI = "URI";

        private string _ksPath;

        private string _ksPass;


        private string _error;
        public string error
        {
            get { return _error; }
        }

        public Signer()
        {
            _ksPath = "";
            _ksPass = "";
            _error = "";

        }

        public void Init(string keyStorePath, string keyStorePassword)
        {
            this._ksPath = keyStorePath;
            this._ksPass = keyStorePassword;
        }

        public bool HasError()
        {
            return !string.IsNullOrEmpty(_error);
        }


        public string Sign(string input, string id, string hash)
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.XmlResolver = null; //disable parser's DTD reading - security meassure
            doc.LoadXml(input);


            XmlElement elementToSign = FindNodeById(doc, NFE_ID_ATT_NAME, id);

            if (elementToSign == null)
            {
                return "";
            }

            SignedXml signedXml = new SignedXml(elementToSign)
            {
                SigningKey = Keys.LoadPrivateKey(_ksPath, _ksPass),
            };

            Reference reference = new Reference
            {
                Uri = "#" + id,
                DigestMethod = DigestAlgUtil.GetDigest(hash)
            };

            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signedXml.AddReference(reference);
            signedXml.SignedInfo.SignatureMethod = SignatureAlgUtil.GetSignature(hash);
            signedXml.SignedInfo.CanonicalizationMethod = ALGO_ID_C14N_OMIT_COMMENTS;
            signedXml.KeyInfo = CreateKeyInfo();

            signedXml.ComputeSignature();

            XmlElement xmlDigitalSignature = signedXml.GetXml();
            elementToSign.AppendChild(doc.ImportNode(xmlDigitalSignature, true));


            return doc.OuterXml;
        }


        public bool Verify(string input)
        {
            X509Certificate2 certificate = Keys.LoadCertificate(_ksPath, _ksPass);
            if (certificate == null)
            {
                this._error = "Problems loading the certificate";
                return false;
            }


            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.XmlResolver = null; //disable parser's DTD reading - security meassure
            doc.LoadXml(input);

            XmlNodeList signatureNodeList = doc.GetElementsByTagName("Signature");
            if (signatureNodeList.Count == 0)
            {
                signatureNodeList = doc.GetElementsByTagName("ds:Signature");
            }

            if (signatureNodeList.Count == 0)
            {
                this._error = "Could not find signatures";
                return false;
            }

            foreach (XmlNode node in signatureNodeList)
            {
                try
                {
                    XmlElement signature = node as XmlElement;
                    string uri = signature.SelectNodes($"//*[@{REFERENCE_URI}]").Item(0).Attributes[REFERENCE_URI].Value.Replace("#", "").Trim();
                    XmlElement element = FindNodeById(doc, NFE_ID_ATT_NAME, uri);
                    if (element == null)
                    {
                        this._error = "could not find signed element";
                        return false;
                    }
                    SignedXml signedXml = new SignedXml(element);
                    signedXml.LoadXml(signature);
                    if (!signedXml.CheckSignature(certificate, true))
                    {
                        return false;
                    }
                }
                catch (Exception ex)
                {
                    this._error = ex.ToString();
                    return false;
                }
            }
            return true;
        }

        private KeyInfo CreateKeyInfo()
        {
            KeyInfo keyInfo = new KeyInfo();
            X509Certificate2 x509Certificate = Keys.LoadCertificate(this._ksPath, this._ksPass);
            KeyInfoX509Data keyInfoX509Data = new KeyInfoX509Data();
            keyInfoX509Data.AddCertificate(x509Certificate);
            keyInfo.AddClause((KeyInfoClause)keyInfoX509Data);
            return keyInfo;
        }

        private XmlElement FindNodeById(XmlDocument doc, string name, string value)
        {
            XmlNodeList nodeList = doc.SelectNodes($"//*[@{name}]");
            if (nodeList == null)
            {
                this._error = "could not find node by id";
                return null;
            }

            foreach (XmlNode node in nodeList)
            {
                string esto = node.Attributes[name]?.Value;
                if (node.Attributes[name]?.Value == value)
                {
                    return node as XmlElement;
                }
            }
            this._error = "could not find node to sign";
            return null;
        }
    }
}
