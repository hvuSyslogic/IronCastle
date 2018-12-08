using System.Text;

namespace org.bouncycastle.pqc.crypto.test
{

	using TestCase = junit.framework.TestCase;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using XMSS = org.bouncycastle.pqc.crypto.xmss.XMSS;
	using XMSSMT = org.bouncycastle.pqc.crypto.xmss.XMSSMT;
	using XMSSMTParameters = org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
	using XMSSParameters = org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
	using XMSSPrivateKeyParameters = org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
	using Arrays = org.bouncycastle.util.Arrays;
	using Base64 = org.bouncycastle.util.encoders.Base64;

	/// <summary>
	/// Test cases for XMSSMTPrivateKey class.
	/// </summary>
	public class XMSSMTPrivateKeyTest : TestCase
	{
		public virtual void testPrivateKeySerialisation()
		{
			string stream = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAArO0ABXNyACJzdW4ucm1pLnNlcnZlci5BY3RpdmF0aW9uR3JvdXBJbXBsT+r9SAwuMqcCAARaAA1ncm91cEluYWN0aXZlTAAGYWN0aXZldAAVTGphdmEvdXRpbC9IYXNodGFibGU7TAAHZ3JvdXBJRHQAJ0xqYXZhL3JtaS9hY3RpdmF0aW9uL0FjdGl2YXRpb25Hcm91cElEO0wACWxvY2tlZElEc3QAEExqYXZhL3V0aWwvTGlzdDt4cgAjamF2YS5ybWkuYWN0aXZhdGlvbi5BY3RpdmF0aW9uR3JvdXCVLvKwBSnVVAIAA0oAC2luY2FybmF0aW9uTAAHZ3JvdXBJRHEAfgACTAAHbW9uaXRvcnQAJ0xqYXZhL3JtaS9hY3RpdmF0aW9uL0FjdGl2YXRpb25Nb25pdG9yO3hyACNqYXZhLnJtaS5zZXJ2ZXIuVW5pY2FzdFJlbW90ZU9iamVjdEUJEhX14n4xAgADSQAEcG9ydEwAA2NzZnQAKExqYXZhL3JtaS9zZXJ2ZXIvUk1JQ2xpZW50U29ja2V0RmFjdG9yeTtMAANzc2Z0AChMamF2YS9ybWkvc2VydmVyL1JNSVNlcnZlclNvY2tldEZhY3Rvcnk7eHIAHGphdmEucm1pLnNlcnZlci5SZW1vdGVTZXJ2ZXLHGQcSaPM5+wIAAHhyABxqYXZhLnJtaS5zZXJ2ZXIuUmVtb3RlT2JqZWN002G0kQxhMx4DAAB4cHcSABBVbmljYXN0U2VydmVyUmVmeAAAFbNwcAAAAAAAAAAAcHAAcHBw";

			XMSSParameters @params = new XMSSParameters(10, new SHA256Digest());

			byte[] output = Base64.decode((stream).GetBytes(Encoding.UTF8));


			//Simple Exploit

			try
			{
				(new XMSSPrivateKeyParameters.Builder(@params)).withPrivateKey(output, @params).build();
			}
			catch (IllegalArgumentException e)
			{
				assertTrue(e.getCause() is IOException);
			}

			//Same Exploit other method

			XMSS xmss2 = new XMSS(@params, new SecureRandom());

			xmss2.generateKeys();

			byte[] publicKey = xmss2.exportPublicKey();

			try
			{
				xmss2.importState(output, publicKey);
			}
			catch (IllegalArgumentException e)
			{
				assertTrue(e.getCause() is IOException);
			}
		}

		public virtual void testPrivateKeyParsingSHA256()
		{
			XMSSMTParameters @params = new XMSSMTParameters(20, 10, new SHA256Digest());
			XMSSMT mt = new XMSSMT(@params, new SecureRandom());
			mt.generateKeys();
			byte[] privateKey = mt.exportPrivateKey();
			byte[] publicKey = mt.exportPublicKey();

			mt.importState(privateKey, publicKey);

			assertTrue(Arrays.areEqual(privateKey, mt.exportPrivateKey()));
		}
	}

}