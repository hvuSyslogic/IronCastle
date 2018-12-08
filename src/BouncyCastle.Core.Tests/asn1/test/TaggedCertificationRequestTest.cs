namespace org.bouncycastle.asn1.test
{
	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using CertificationRequest = org.bouncycastle.asn1.cmc.CertificationRequest;
	using TaggedCertificationRequest = org.bouncycastle.asn1.cmc.TaggedCertificationRequest;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class TaggedCertificationRequestTest : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new TaggedCertificationRequestTest());
		}

		public override string getName()
		{
			return "TaggedCertificationRequestTest";
		}


		private static byte[] req1 = Base64.decode("MIHoMIGTAgEAMC4xDjAMBgNVBAMTBVRlc3QyMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF" + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALlEt31Tzt2MlcOljvacJgzQVhmlMoqAOgqJ9Pgd3Gux" + "Z7/WcIlgW4QCB7WZT21O1YoghwBhPDMcNGrHei9kHQkCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA0EA" + "NDEI4ecNtJ3uHwGGlitNFq9WxcoZ0djbQJ5hABMotav6gtqlrwKXY2evaIrsNwkJtNdwwH18aQDU" + "KCjOuBL38Q==");


		public override void performTest()
		{
			CertificationRequest r = CertificationRequest.getInstance(req1);
			TaggedCertificationRequest tcr = new TaggedCertificationRequest(new BodyPartID(10L), r);

			byte[] b = tcr.getEncoded();
			TaggedCertificationRequest tcrResp = TaggedCertificationRequest.getInstance(b);

			isEquals(tcrResp,tcr);
		}
	}

}