// See https://aka.ms/new-console-template for more information
using SingXml;

Console.WriteLine("Hello, World!");

string xml = "<NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\"><infNFe Id=\"NFe35240223236228000143550020000000031383323566\" versao=\"4.00\"><ide><cUF>35</cUF><cNF>38145756</cNF><natOp>VENDA PROD ADQUIRIDO CONSUMIDOR</natOp><mod>55</mod>";
xml += "<serie>2</serie><nNF>3</nNF><dhEmi>2024-02-05T16:09:54-03:00</dhEmi><tpNF>1</tpNF><idDest>1</idDest><cMunFG>3538709</cMunFG><tpImp>2</tpImp><tpEmis>1</tpEmis><cDV>6</cDV><tpAmb>1</tpAmb><finNFe>1</finNFe><indFinal>1</indFinal>";
xml += "<indPres>1</indPres><procEmi>0</procEmi><verProc>4.00</verProc></ide><emit><CNPJ>1240012343</CNPJ><xNome>EMPRESA</xNome><xFant>EMPRESA</xFant><enderEmit><xLgr>TRAVESSA </xLgr><nro>43</nro><xBairro>EUROPA</xBairro>";
xml += "<cMun>3538709</cMun><xMun>SAO PAULO</xMun><UF>SP</UF><CEP>1594984</CEP><cPais>1058</cPais><xPais>BRASIL</xPais><fone>8494984984</fone></enderEmit><IE>5494984</IE><CRT>1</CRT></emit><dest><CPF>6449485498</CPF>";
xml += "<xNome>CLIENTE</xNome><enderDest><xLgr>CLIENTE</xLgr><nro>85</nro><xBairro>TERRAS </xBairro><cMun>3538709</cMun><xMun>SAO PAULO</xMun><UF>SP</UF><CEP>1854949</CEP><cPais>1058</cPais><xPais>BRASIL</xPais></enderDest><indIEDest>9</indIEDest>";
xml += "</dest><det nItem=\"1\"><prod><cProd>BRCN25OANA</cProd><cEAN>SEM GTIN</cEAN><xProd>BRINCO</xProd><NCM>71131900</NCM><CFOP>5102</CFOP><uCom>PAR</uCom><qCom>1.0000</qCom><vUnCom>40000.000000</vUnCom><vProd>40000.00</vProd>";
xml += "<cEANTrib>SEM GTIN</cEANTrib><uTrib>PAR</uTrib><qTrib>1.0000</qTrib><vUnTrib>40000.000000</vUnTrib><indTot>1</indTot></prod><imposto><ICMS><ICMSSN102><orig>0</orig><CSOSN>102</CSOSN></ICMSSN102></ICMS><PIS><PISOutr><CST>49</CST>";
xml += "<vBC>0</vBC><pPIS>0</pPIS><vPIS>0</vPIS></PISOutr></PIS><COFINS><COFINSOutr><CST>49</CST><vBC>0</vBC><pCOFINS>0</pCOFINS><vCOFINS>0</vCOFINS></COFINSOutr></COFINS></imposto></det><total><ICMSTot><vBC>0.00</vBC><vICMS>0.00</vICMS>";
xml += "<vICMSDeson>0</vICMSDeson><vFCP>0</vFCP><vBCST>0</vBCST><vST>0</vST><vFCPST>0</vFCPST><vFCPSTRet>0</vFCPSTRet><vProd>40000.00</vProd><vFrete>0</vFrete><vSeg>0</vSeg><vDesc>0</vDesc><vII>0</vII><vIPI>0.00</vIPI>";
xml += "<vIPIDevol>0</vIPIDevol><vPIS>0.00</vPIS><vCOFINS>0.00</vCOFINS><vOutro>0</vOutro><vNF>40000.00</vNF></ICMSTot></total><transp><modFrete>9</modFrete></transp><pag><detPag><indPag>0</indPag><tPag>17</tPag><vPag>40000.00</vPag>";
xml += "</detPag></pag><infAdic><infAdFisco>DOCUMENTO EMITIDO POR ME OU EPP OPTANTE PELO SIMPLES NACIONAL NAO GERA DIREITO A CREDITO FISCAL DE IPI Permite aproveitamento de Credito SN 544.00 ref aliquota ICMS 1.36</infAdFisco>";
xml += "</infAdic></infNFe></NFe>";


string keyStorePath = "C:\\tmp\\dummycerts\\RSA_sha256_2048\\sha256_cert.pfx";
string keyStorePassword = "dummy";

Signer signer = new Signer();
signer.Init(keyStorePath, keyStorePassword);
string signed = signer.Sign(xml, "NFe35240223236228000143550020000000031383323566", "SHA1");
Console.WriteLine("SIGNED: " + signed);
bool verification = signer.Verify(signed);
Console.WriteLine("VERIFICATION: " + verification);

if(signer.HasError())
{
    Console.WriteLine(signer.error);
}
