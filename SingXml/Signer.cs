using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace SingXml
{
    public class Signer
    {
        internal static string ALGO_ID_C14N_OMIT_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
        public string XML_TAG { get; set; } = "NFe";
        public string XML_ID_ATT_NAME { get; set; } = "Id";
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
            XmlDocument doc = new XmlDocument
            {
                PreserveWhitespace = true,
                XmlResolver = null // disable parser's DTD reading - medida de segurança
            };
            doc.LoadXml(input);

            XmlElement elementToSign = FindNodeById(doc, XML_ID_ATT_NAME, id);
            if (elementToSign == null)
            {
                return "";
            }

            // Adicionado: assinatura será anexada na tag raiz (NFe) em vez de dentro do elemento assinado
            XmlElement elementToAddSign = doc.DocumentElement;
            if (elementToAddSign == null || !string.Equals(elementToAddSign.LocalName, XML_TAG, StringComparison.OrdinalIgnoreCase))
            {
                // tenta localizar a tag NFe caso a raiz não seja NFe
                XmlNodeList nfeNodes = doc.GetElementsByTagName(XML_TAG);
                if (nfeNodes != null && nfeNodes.Count > 0)
                {
                    elementToAddSign = nfeNodes[0] as XmlElement;
                }
            }

            // Carrega certificado apenas uma vez por operação
            X509Certificate2 cert = null;
            try
            {
                cert = Keys.LoadCertificate(_ksPath, _ksPass);
                if (cert == null)
                {
                    this._error = "Problemas ao carregar o certificado";
                    return "";
                }

                SignedXml signedXml = new SignedXml(elementToSign)
                {
                    SigningKey = Keys.LoadPrivateKey(_ksPath, _ksPass)
                };

                Reference reference = new Reference
                {
                    Uri = "#" + id,
                    DigestMethod = DigestAlgUtil.GetDigest(hash)
                };

                // Adiciona o transform enveloped e o transform de canonicalização inclusiva (esperado pela SEFAZ)
                reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                reference.AddTransform(new XmlDsigC14NTransform());

                signedXml.AddReference(reference);
                signedXml.SignedInfo.SignatureMethod = SignatureAlgUtil.GetSignature(hash);

                // Use canonicalização inclusiva — correspondente ao transform adicionado e ao que a SEFAZ espera
                signedXml.SignedInfo.CanonicalizationMethod = ALGO_ID_C14N_OMIT_COMMENTS;
                signedXml.KeyInfo = CreateKeyInfo(cert);

                signedXml.ComputeSignature();

                XmlElement xmlDigitalSignature = signedXml.GetXml();

                if (elementToAddSign == null)
                {
                    // fallback: anexar onde o Cris originalmente fez (elemento assinado)
                    elementToSign.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
                }
                else
                {
                    elementToAddSign.AppendChild(doc.ImportNode(xmlDigitalSignature, true));
                }

                return doc.OuterXml;
            }
            finally
            {
                cert?.Dispose();
            }
        }

        public bool Verify(string input)
        {
            X509Certificate2 certificate = Keys.LoadCertificate(_ksPath, _ksPass);
            if (certificate == null)
            {
                this._error = "Problemas ao carregar o certificado";
                return false;
            }

            try
            {
                XmlDocument doc = new XmlDocument
                {
                    PreserveWhitespace = true,
                    XmlResolver = null // disable parser's DTD reading - medida de segurança
                };
                doc.LoadXml(input);

                XmlNodeList signatureNodeList = doc.GetElementsByTagName("Signature");
                if (signatureNodeList.Count == 0)
                {
                    signatureNodeList = doc.GetElementsByTagName("ds:Signature");
                }

                if (signatureNodeList.Count == 0)
                {
                    this._error = "Não foi possível encontrar assinaturas";
                    return false;
                }

                foreach (XmlNode node in signatureNodeList)
                {
                    try
                    {
                        XmlElement signature = node as XmlElement;
                        if (signature == null)
                        {
                            this._error = "Nó de assinatura inválido";
                            return false;
                        }

                        // Busca mais robusta pela URI do Reference dentro da Signature
                        string uri = null;
                        XmlNodeList referenceNodes = signature.GetElementsByTagName("Reference");
                        if (referenceNodes != null && referenceNodes.Count > 0)
                        {
                            XmlElement refEl = referenceNodes[0] as XmlElement;
                            if (refEl != null && refEl.HasAttribute(REFERENCE_URI))
                            {
                                uri = refEl.GetAttribute(REFERENCE_URI).Replace("#", "").Trim();
                            }
                        }

                        if (string.IsNullOrEmpty(uri))
                        {
                            // fallback para busca global (compatibilidade)
                            XmlNode uriNode = signature.SelectSingleNode($"//*[@{REFERENCE_URI}]");
                            if (uriNode?.Attributes?[REFERENCE_URI] != null)
                            {
                                uri = uriNode.Attributes[REFERENCE_URI].Value.Replace("#", "").Trim();
                            }
                        }

                        if (string.IsNullOrEmpty(uri))
                        {
                            this._error = "Não foi possível localizar URI da referência na assinatura";
                            return false;
                        }

                        XmlElement element = FindNodeById(doc, XML_ID_ATT_NAME, uri);
                        if (element == null)
                        {
                            this._error = "Não foi possível encontrar o elemento assinado";
                            return false;
                        }

                        SignedXml signedXml = new SignedXml(element);
                        signedXml.LoadXml(signature);
                        if (!signedXml.CheckSignature(certificate, true))
                        {
                            this._error = "Assinatura inválida";
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
            finally
            {
                certificate.Dispose();
            }
        }

        private KeyInfo CreateKeyInfo(X509Certificate2 x509Certificate)
        {
            KeyInfo keyInfo = new KeyInfo();
            KeyInfoX509Data keyInfoX509Data = new KeyInfoX509Data();
            keyInfoX509Data.AddCertificate(x509Certificate);
            keyInfo.AddClause((KeyInfoClause)keyInfoX509Data);
            return keyInfo;
        }

        private XmlElement FindNodeById(XmlDocument doc, string name, string value)
        {
            // Mantive pesquisa por atributo, mas mais eficiente: selecionar apenas nós cujo atributo tem o valor exato
            XmlNode node = doc.SelectSingleNode($"//*[@{name}='{value}']");
            if (node == null)
            {
                // fallback para compatibilidade com documentos peculiares
                XmlNodeList nodeList = doc.SelectNodes($"//*[@{name}]");
                if (nodeList == null || nodeList.Count == 0)
                {
                    this._error = "Não foi possível encontrar nó por id";
                    return null;
                }

                foreach (XmlNode n in nodeList)
                {
                    if (n.Attributes?[name]?.Value == value)
                    {
                        return n as XmlElement;
                    }
                }

                this._error = "Não foi possível encontrar nó para assinar";
                return null;
            }

            return node as XmlElement;
        }
    }
}
