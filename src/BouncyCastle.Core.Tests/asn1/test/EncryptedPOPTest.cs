using System;

namespace org.bouncycastle.asn1.test
{

	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using CertificationRequest = org.bouncycastle.asn1.cmc.CertificationRequest;
	using EncryptedPOP = org.bouncycastle.asn1.cmc.EncryptedPOP;
	using TaggedCertificationRequest = org.bouncycastle.asn1.cmc.TaggedCertificationRequest;
	using TaggedRequest = org.bouncycastle.asn1.cmc.TaggedRequest;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class EncryptedPOPTest : SimpleTest
	{
		public override string getName()
		{
			return "EncryptedPOPTest";
		}

		private byte[] req1 = Base64.decode("MIHoMIGTAgEAMC4xDjAMBgNVBAMTBVRlc3QyMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF" + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALlEt31Tzt2MlcOljvacJgzQVhmlMoqAOgqJ9Pgd3Gux" + "Z7/WcIlgW4QCB7WZT21O1YoghwBhPDMcNGrHei9kHQkCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA0EA" + "NDEI4ecNtJ3uHwGGlitNFq9WxcoZ0djbQJ5hABMotav6gtqlrwKXY2evaIrsNwkJtNdwwH18aQDU" + "KCjOuBL38Q==");

		public override void performTest()
		{
			// All Object Identifiers are not real!
			TaggedRequest taggedRequest = new TaggedRequest(new TaggedCertificationRequest(new BodyPartID(10L), CertificationRequest.getInstance(req1)));
			ContentInfo cms = new ContentInfo(new ASN1ObjectIdentifier("1.2.3"), new ASN1Integer(12L));
			AlgorithmIdentifier thePopID = new AlgorithmIdentifier(new ASN1ObjectIdentifier("2.2.5.2"));
			AlgorithmIdentifier whitenessID = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.5.2.5"));
			byte[] whiteness = "Fish and Chips".GetBytes();

			EncryptedPOP ep = new EncryptedPOP(taggedRequest, cms, thePopID, whitenessID, whiteness);
			byte[] b = ep.getEncoded();
			EncryptedPOP epResult = EncryptedPOP.getInstance(b);

			isEquals("TaggedRequest", epResult.getRequest(), taggedRequest);
			isEquals("ContentInfo (cms)", epResult.getCms(), cms);
			isEquals("Pop Algorithm ID", epResult.getThePOPAlgID(), thePopID);
			isEquals("Whiteness ID", epResult.getWitnessAlgID(), whitenessID);
			isTrue("Whiteness", areEqual(epResult.getWitness(), whiteness));

			// Test sequence length

			try
			{
				EncryptedPOP.getInstance(new DERSequence(new ASN1Integer(1L)));
				fail("Sequence must be 5 items long.");
			}
			catch (Exception t)
			{
				isEquals(t.GetType(), typeof(IllegalArgumentException));
			}
		}

		public static void Main(string[] args)
		{
			runTest(new EncryptedPOPTest());
		}
	}

}