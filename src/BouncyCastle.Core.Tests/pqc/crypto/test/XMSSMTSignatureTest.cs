namespace org.bouncycastle.pqc.crypto.test
{
	using TestCase = junit.framework.TestCase;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using XMSSMT = org.bouncycastle.pqc.crypto.xmss.XMSSMT;
	using XMSSMTParameters = org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
	using XMSSMTSignature = org.bouncycastle.pqc.crypto.xmss.XMSSMTSignature;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Test cases for XMSS^MT signature class.
	/// </summary>
	public class XMSSMTSignatureTest : TestCase
	{

		public virtual void testSignatureParsingSHA256()
		{
			int totalHeight = 6;
			int layers = 3;
			byte[] message = new byte[1024];
			XMSSMTParameters @params = new XMSSMTParameters(totalHeight, layers, new SHA256Digest());
			XMSSMT xmssMT = new XMSSMT(@params, new NullPRNG());
			xmssMT.generateKeys();
			byte[] signature1 = xmssMT.sign(message);
			XMSSMTSignature mtSignature = (new XMSSMTSignature.Builder(@params)).withSignature(signature1).build();
			byte[] signature2 = mtSignature.toByteArray();
			assertTrue(Arrays.areEqual(signature1, signature2));
		}

		public virtual void testConstructor()
		{
			XMSSMTParameters @params = new XMSSMTParameters(20, 10, new SHA256Digest());
			XMSSMTSignature sig = null;
			try
			{
				sig = (new XMSSMTSignature.Builder(@params)).build();
			}
			catch (IllegalArgumentException ex)
			{
				ex.printStackTrace();
			}
			byte[] sigByte = sig.toByteArray();
			/* check everything is 0 */
			for (int i = 0; i < sigByte.Length; i++)
			{
				assertEquals(0x00, sigByte[i]);
			}
		}
	}

}