using org.bouncycastle.asn1.cms;

using System.Text;

namespace org.bouncycastle.jce.provider.test
{
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using DERTaggedObject = org.bouncycastle.asn1.DERTaggedObject;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using SignedData = org.bouncycastle.asn1.cms.SignedData;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using X509AttributeCertificate = org.bouncycastle.x509.X509AttributeCertificate;
	using X509CertificatePair = org.bouncycastle.x509.X509CertificatePair;
	using X509StreamParser = org.bouncycastle.x509.X509StreamParser;


	public class X509StreamParserTest : SimpleTest
	{
		internal byte[] attrCert = Base64.decode("MIIHQDCCBqkCAQEwgZChgY2kgYowgYcxHDAaBgkqhkiG9w0BCQEWDW1sb3JjaEB2" + "dC5lZHUxHjAcBgNVBAMTFU1hcmt1cyBMb3JjaCAobWxvcmNoKTEbMBkGA1UECxMS" + "VmlyZ2luaWEgVGVjaCBVc2VyMRAwDgYDVQQLEwdDbGFzcyAyMQswCQYDVQQKEwJ2" + "dDELMAkGA1UEBhMCVVMwgYmkgYYwgYMxGzAZBgkqhkiG9w0BCQEWDHNzaGFoQHZ0" + "LmVkdTEbMBkGA1UEAxMSU3VtaXQgU2hhaCAoc3NoYWgpMRswGQYDVQQLExJWaXJn" + "aW5pYSBUZWNoIFVzZXIxEDAOBgNVBAsTB0NsYXNzIDExCzAJBgNVBAoTAnZ0MQsw" + "CQYDVQQGEwJVUzANBgkqhkiG9w0BAQQFAAIBBTAiGA8yMDAzMDcxODE2MDgwMloY" + "DzIwMDMwNzI1MTYwODAyWjCCBU0wggVJBgorBgEEAbRoCAEBMYIFORaCBTU8UnVs" + "ZSBSdWxlSWQ9IkZpbGUtUHJpdmlsZWdlLVJ1bGUiIEVmZmVjdD0iUGVybWl0Ij4K" + "IDxUYXJnZXQ+CiAgPFN1YmplY3RzPgogICA8U3ViamVjdD4KICAgIDxTdWJqZWN0" + "TWF0Y2ggTWF0Y2hJZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5j" + "dGlvbjpzdHJpbmctZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlw" + "ZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjc3RyaW5nIj4KICAg" + "ICAgIENOPU1hcmt1cyBMb3JjaDwvQXR0cmlidXRlVmFsdWU+CiAgICAgPFN1Ympl" + "Y3RBdHRyaWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFt" + "ZXM6dGM6eGFjbWw6MS4wOnN1YmplY3Q6c3ViamVjdC1pZCIgRGF0YVR5cGU9Imh0" + "dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hI3N0cmluZyIgLz4gCiAgICA8" + "L1N1YmplY3RNYXRjaD4KICAgPC9TdWJqZWN0PgogIDwvU3ViamVjdHM+CiAgPFJl" + "c291cmNlcz4KICAgPFJlc291cmNlPgogICAgPFJlc291cmNlTWF0Y2ggTWF0Y2hJ" + "ZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5jdGlvbjpzdHJpbmct" + "ZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlwZT0iaHR0cDovL3d3" + "dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIj4KICAgICAgaHR0cDovL3p1" + "bmkuY3MudnQuZWR1PC9BdHRyaWJ1dGVWYWx1ZT4KICAgICA8UmVzb3VyY2VBdHRy" + "aWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6" + "eGFjbWw6MS4wOnJlc291cmNlOnJlc291cmNlLWlkIiBEYXRhVHlwZT0iaHR0cDov" + "L3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIiAvPiAKICAgIDwvUmVz" + "b3VyY2VNYXRjaD4KICAgPC9SZXNvdXJjZT4KICA8L1Jlc291cmNlcz4KICA8QWN0" + "aW9ucz4KICAgPEFjdGlvbj4KICAgIDxBY3Rpb25NYXRjaCBNYXRjaElkPSJ1cm46" + "b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmZ1bmN0aW9uOnN0cmluZy1lcXVhbCI+" + "CiAgICAgPEF0dHJpYnV0ZVZhbHVlIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9y" + "Zy8yMDAxL1hNTFNjaGVtYSNzdHJpbmciPgpEZWxlZ2F0ZSBBY2Nlc3MgICAgIDwv" + "QXR0cmlidXRlVmFsdWU+CgkgIDxBY3Rpb25BdHRyaWJ1dGVEZXNpZ25hdG9yIEF0" + "dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmFjdGlvbjph" + "Y3Rpb24taWQiIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNj" + "aGVtYSNzdHJpbmciIC8+IAogICAgPC9BY3Rpb25NYXRjaD4KICAgPC9BY3Rpb24+" + "CiAgPC9BY3Rpb25zPgogPC9UYXJnZXQ+CjwvUnVsZT4KMA0GCSqGSIb3DQEBBAUA" + "A4GBAGiJSM48XsY90HlYxGmGVSmNR6ZW2As+bot3KAfiCIkUIOAqhcphBS23egTr" + "6asYwy151HshbPNYz+Cgeqs45KkVzh7bL/0e1r8sDVIaaGIkjHK3CqBABnfSayr3" + "Rd1yBoDdEv8Qb+3eEPH6ab9021AsLEnJ6LWTmybbOpMNZ3tv");

		public override void performTest()
		{
			X509StreamParser parser = X509StreamParser.getInstance("Certificate", "BC");

			parser.init(new ByteArrayInputStream(CertPathTest.rootCertBin));
			X509Certificate rootCert = (X509Certificate)parser.read();

			parser = X509StreamParser.getInstance("CRL", "BC");

			parser.init(new ByteArrayInputStream(CertPathTest.rootCrlBin));


			X509CRL rootCrl = (X509CRL)parser.read();

			parser = X509StreamParser.getInstance("AttributeCertificate", "BC");

			parser.init(new ByteArrayInputStream(attrCert));

			X509AttributeCertificate aCert = (X509AttributeCertificate)parser.read();

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			bOut.write(CertPathTest.rootCertBin);
			bOut.write(CertPathTest.interCertBin);
			bOut.write(CertPathTest.finalCertBin);

			parser = X509StreamParser.getInstance("Certificate", "BC");

			parser.init(bOut.toByteArray());

			Collection res = parser.readAll();

			if (res.size() != 3)
			{
				fail("wrong number of certificates found");
			}

			bOut = new ByteArrayOutputStream();

			bOut.write(CertPathTest.rootCrlBin);
			bOut.write(CertPathTest.interCrlBin);

			parser = X509StreamParser.getInstance("CRL", "BC");

			parser.init(bOut.toByteArray());

			res = parser.readAll();

			if (res.size() != 2)
			{
				fail("wrong number of CRLs found");
			}

			bOut = new ByteArrayOutputStream();

			bOut.write(attrCert);
			bOut.write(attrCert);

			parser = X509StreamParser.getInstance("AttributeCertificate", "BC");

			parser.init(bOut.toByteArray());

			res = parser.readAll();

			if (res.size() != 2)
			{
				fail("wrong number of Attribute Certificates found");
			}

			//
			// PEM tests
			//
			parser = X509StreamParser.getInstance("Certificate", "BC");

			parser.init(PEMData.CERTIFICATE_1.GetBytes(Encoding.ASCII));

			res = parser.readAll();

			if (res.size() != 1)
			{
				fail("wrong number of Certificates found");
			}

			parser = X509StreamParser.getInstance("Certificate", "BC");

			parser.init(PEMData.CERTIFICATE_2.GetBytes(Encoding.ASCII));

			res = parser.readAll();

			if (res.size() != 1)
			{
				fail("wrong number of Certificates found");
			}

			parser = X509StreamParser.getInstance("CRL", "BC");

			parser.init(PEMData.CRL_1.GetBytes(Encoding.ASCII));

			res = parser.readAll();

			if (res.size() != 1)
			{
				fail("wrong number of CRLs found");
			}

			parser = X509StreamParser.getInstance("CRL", "BC");

			parser.init(PEMData.CRL_2.GetBytes(Encoding.ASCII));

			res = parser.readAll();

			if (res.size() != 1)
			{
				fail("wrong number of CRLs found");
			}

			parser = X509StreamParser.getInstance("AttributeCertificate", "BC");

			parser.init(PEMData.ATTRIBUTE_CERTIFICATE_1.GetBytes(Encoding.ASCII));

			res = parser.readAll();

			if (res.size() != 1)
			{
				fail("wrong number of Attribute Certificates found");
			}

			parser = X509StreamParser.getInstance("AttributeCertificate", "BC");

			parser.init(PEMData.ATTRIBUTE_CERTIFICATE_2.GetBytes(Encoding.ASCII));

			res = parser.readAll();

			if (res.size() != 1)
			{
				fail("wrong number of Attribute Certificates found");
			}

			ASN1EncodableVector certs = new ASN1EncodableVector();

			certs.add((new ASN1InputStream(CertPathTest.rootCertBin)).readObject());
			certs.add(new DERTaggedObject(false, 2, (new ASN1InputStream(attrCert)).readObject()));

			ASN1EncodableVector crls = new ASN1EncodableVector();

			crls.add((new ASN1InputStream(CertPathTest.rootCrlBin)).readObject());

			//
			// cross certificate pairs
			//
			parser = X509StreamParser.getInstance("CertificatePair", "BC");

			parser.init((new X509CertificatePair(rootCert, rootCert)).getEncoded());

			res = parser.readAll();

			if (res.size() != 1)
			{
				fail("wrong number of CertificatePairs found");
			}

			//
			// PKCS7
			//
			SignedData sigData = new SignedData(new DERSet(), new ContentInfo(CMSObjectIdentifiers_Fields.data, null), new DERSet(certs), new DERSet(crls), new DERSet());

			ContentInfo info = new ContentInfo(CMSObjectIdentifiers_Fields.signedData, sigData);

			parser = X509StreamParser.getInstance("Certificate", "BC");

			parser.init(info.getEncoded());

			res = parser.readAll();

			if (res.size() != 1)
			{
				fail("wrong number of Certificates found");
			}

			parser = X509StreamParser.getInstance("CRL", "BC");

			parser.init(info.getEncoded());

			res = parser.readAll();

			if (res.size() != 1)
			{
				fail("wrong number of CRLs found");
			}

			parser = X509StreamParser.getInstance("AttributeCertificate", "BC");

			parser.init(info.getEncoded());

			res = parser.readAll();

			if (res.size() != 1)
			{
				fail("wrong number of Attribute Certificates found");
			}

			// data with no certificates or CRLs

			sigData = new SignedData(new DERSet(), new ContentInfo(CMSObjectIdentifiers_Fields.data, null), new DERSet(), new DERSet(), new DERSet());

			info = new ContentInfo(CMSObjectIdentifiers_Fields.signedData, sigData);

			parser = X509StreamParser.getInstance("Certificate", "BC");

			parser.init(info.getEncoded());

			res = parser.readAll();

			if (res.size() != 0)
			{
				fail("wrong number of Certificates found - expected 0");
			}

			parser = X509StreamParser.getInstance("CRL", "BC");

			parser.init(info.getEncoded());

			res = parser.readAll();

			if (res.size() != 0)
			{
				fail("wrong number of CRLs found - expected 0");
			}

			parser = X509StreamParser.getInstance("AttributeCertificate", "BC");

			parser.init(info.getEncoded());

			res = parser.readAll();

			if (res.size() != 0)
			{
				fail("wrong number of Attribute Certificates found - expected 0");
			}

			// data with absent certificates and CRLs
			sigData = new SignedData(new DERSet(), new ContentInfo(CMSObjectIdentifiers_Fields.data, null), null, null, new DERSet());

			info = new ContentInfo(CMSObjectIdentifiers_Fields.signedData, sigData);

			parser = X509StreamParser.getInstance("Certificate", "BC");

			parser.init(info.getEncoded());

			res = parser.readAll();

			if (res.size() != 0)
			{
				fail("wrong number of Certificates found - expected 0");
			}

			parser = X509StreamParser.getInstance("CRL", "BC");

			parser.init(info.getEncoded());

			res = parser.readAll();

			if (res.size() != 0)
			{
				fail("wrong number of CRLs found - expected 0");
			}

			parser = X509StreamParser.getInstance("AttributeCertificate", "BC");

			parser.init(info.getEncoded());

			res = parser.readAll();

			if (res.size() != 0)
			{
				fail("wrong number of Attribute Certificates found - expected 0");
			}
		}

		public override string getName()
		{
			return "X509StreamParser";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new X509StreamParserTest());
		}

	}

}