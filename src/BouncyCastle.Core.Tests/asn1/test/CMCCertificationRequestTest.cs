namespace org.bouncycastle.asn1.test
{

	using CertificationRequest = org.bouncycastle.asn1.cmc.CertificationRequest;
	using Arrays = org.bouncycastle.util.Arrays;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class CMCCertificationRequestTest : SimpleTest
	{
		internal byte[] req1 = Base64.decode("MIHoMIGTAgEAMC4xDjAMBgNVBAMTBVRlc3QyMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF" + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALlEt31Tzt2MlcOljvacJgzQVhmlMoqAOgqJ9Pgd3Gux" + "Z7/WcIlgW4QCB7WZT21O1YoghwBhPDMcNGrHei9kHQkCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA0EA" + "NDEI4ecNtJ3uHwGGlitNFq9WxcoZ0djbQJ5hABMotav6gtqlrwKXY2evaIrsNwkJtNdwwH18aQDU" + "KCjOuBL38Q==");

		internal byte[] req2 = Base64.decode("MIIB6TCCAVICAQAwgagxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRQwEgYDVQQH" + "EwtTYW50YSBDbGFyYTEMMAoGA1UEChMDQUJCMVEwTwYDVQQLHEhQAAAAAAAAAG8AAAAAAAAAdwAA" + "AAAAAABlAAAAAAAAAHIAAAAAAAAAIAAAAAAAAABUAAAAAAAAABxIAAAAAAAARAAAAAAAAAAxDTAL" + "BgNVBAMTBGJsdWUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANETRZ+6occCOrFxNhfKIp4C" + "mMkxwhBNb7TnnahpbM9O0r4hrBPcfYuL7u9YX/jN0YNUP+/CiT39HhSe/bikaBPDEyNsl988I8vX" + "piEdgxYq/+LTgGHbjRsRYCkPtmzwBbuBldNF8bV7pu0v4UScSsExmGqqDlX1TbPU8KkPU1iTAgMB" + "AAGgADANBgkqhkiG9w0BAQQFAAOBgQAFbrs9qUwh93CtETk7DeUD5HcdCnxauo1bck44snSV6MZV" + "OCIGaYu1501kmhEvAtVVRr6SEHwimfQDDIjnrWwYsEr/DT6tkTZAbfRd3qUu3iKjT0H0vlUZp0hJ" + "66mINtBM84uZFBfoXiWY8M3FuAnGmvy6ah/dYtJorTxLKiGkew==");

		public override string getName()
		{
			return "CMCCertificationRequestTest";
		}

		public virtual void certReqTest(string testName, byte[] req)
		{
			CertificationRequest r = CertificationRequest.getInstance(req);

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			DEROutputStream dOut = new DEROutputStream(bOut);

			dOut.writeObject(r.toASN1Primitive());

			byte[] bytes = bOut.toByteArray();

			if (bytes.Length != req.Length)
			{
				fail(testName + " failed length test");
			}

			for (int i = 0; i != req.Length; i++)
			{
				if (bytes[i] != req[i])
				{
					fail(testName + " failed comparison test");
				}
			}
		}

		public override void performTest()
		{
			certReqTest("req1", req1);
			certReqTest("req2", req2);

			CertificationRequest a = CertificationRequest.getInstance(req1);
			CertificationRequest b = new CertificationRequest(a.getSubject(), a.getSubjectPublicKeyAlgorithm(), a.getSubjectPublicKey(), a.getAttributes(), a.getSignatureAlgorithm(), a.getSignature());

			isTrue(Arrays.areEqual(a.getEncoded(), b.getEncoded()));
		}


		public static void Main(string[] args)
		{
			runTest(new CMCCertificationRequestTest());
		}
	}

}