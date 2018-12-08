using System;

namespace org.bouncycastle.asn1.test
{

	using CertificationRequest = org.bouncycastle.asn1.pkcs.CertificationRequest;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	public class PKCS10Test : Test
	{
		internal byte[] req1 = Base64.decode("MIHoMIGTAgEAMC4xDjAMBgNVBAMTBVRlc3QyMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF" + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALlEt31Tzt2MlcOljvacJgzQVhmlMoqAOgqJ9Pgd3Gux" + "Z7/WcIlgW4QCB7WZT21O1YoghwBhPDMcNGrHei9kHQkCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA0EA" + "NDEI4ecNtJ3uHwGGlitNFq9WxcoZ0djbQJ5hABMotav6gtqlrwKXY2evaIrsNwkJtNdwwH18aQDU" + "KCjOuBL38Q==");

		internal byte[] req2 = Base64.decode("MIIB6TCCAVICAQAwgagxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRQwEgYDVQQH" + "EwtTYW50YSBDbGFyYTEMMAoGA1UEChMDQUJCMVEwTwYDVQQLHEhQAAAAAAAAAG8AAAAAAAAAdwAA" + "AAAAAABlAAAAAAAAAHIAAAAAAAAAIAAAAAAAAABUAAAAAAAAABxIAAAAAAAARAAAAAAAAAAxDTAL" + "BgNVBAMTBGJsdWUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANETRZ+6occCOrFxNhfKIp4C" + "mMkxwhBNb7TnnahpbM9O0r4hrBPcfYuL7u9YX/jN0YNUP+/CiT39HhSe/bikaBPDEyNsl988I8vX" + "piEdgxYq/+LTgGHbjRsRYCkPtmzwBbuBldNF8bV7pu0v4UScSsExmGqqDlX1TbPU8KkPU1iTAgMB" + "AAGgADANBgkqhkiG9w0BAQQFAAOBgQAFbrs9qUwh93CtETk7DeUD5HcdCnxauo1bck44snSV6MZV" + "OCIGaYu1501kmhEvAtVVRr6SEHwimfQDDIjnrWwYsEr/DT6tkTZAbfRd3qUu3iKjT0H0vlUZp0hJ" + "66mINtBM84uZFBfoXiWY8M3FuAnGmvy6ah/dYtJorTxLKiGkew==");

		public virtual string getName()
		{
			return "PKCS10";
		}

		public virtual TestResult pkcs10Test(string testName, byte[] req)
		{
			try
			{
				ByteArrayInputStream bIn = new ByteArrayInputStream(req);
				ASN1InputStream aIn = new ASN1InputStream(bIn);

				CertificationRequest r = new CertificationRequest((ASN1Sequence)aIn.readObject());

				ByteArrayOutputStream bOut = new ByteArrayOutputStream();
				DEROutputStream dOut = new DEROutputStream(bOut);

				dOut.writeObject(r.toASN1Primitive());

				byte[] bytes = bOut.toByteArray();

				if (bytes.Length != req.Length)
				{
					return new SimpleTestResult(false, getName() + ": " + testName + " failed length test");
				}

				for (int i = 0; i != req.Length; i++)
				{
					if (bytes[i] != req[i])
					{
						return new SimpleTestResult(false, getName() + ": " + testName + " failed comparison test");
					}
				}
			}
			catch (Exception e)
			{
				return new SimpleTestResult(false, getName() + ": Exception - " + testName + " " + e.ToString());
			}

			return new SimpleTestResult(true, getName() + ": Okay");
		}

		public virtual TestResult perform()
		{
			TestResult res = pkcs10Test("basic CR", req1);

			if (!res.isSuccessful())
			{
				return res;
			}

			return pkcs10Test("Universal CR", req2);
		}

		public static void Main(string[] args)
		{
			Test test = new PKCS10Test();

			TestResult result = test.perform();

			JavaSystem.@out.println(result);
		}
	}

}