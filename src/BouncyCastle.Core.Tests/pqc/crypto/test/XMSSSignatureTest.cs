namespace org.bouncycastle.pqc.crypto.test
{
	using TestCase = junit.framework.TestCase;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using XMSS = org.bouncycastle.pqc.crypto.xmss.XMSS;
	using XMSSParameters = org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
	using XMSSSignature = org.bouncycastle.pqc.crypto.xmss.XMSSSignature;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Test cases for XMSSSignature class.
	/// </summary>
	public class XMSSSignatureTest : TestCase
	{

		public virtual void testSignatureParsingSHA256()
		{
			XMSSParameters @params = new XMSSParameters(10, new SHA256Digest());
			XMSS xmss = new XMSS(@params, new NullPRNG());
			xmss.generateKeys();
			byte[] message = new byte[1024];
			byte[] sig1 = xmss.sign(message);
			XMSSSignature sig2 = (new XMSSSignature.Builder(@params)).withSignature(sig1).build();

			byte[] sig3 = sig2.toByteArray();
			assertEquals(true, Arrays.areEqual(sig1, sig3));
		}

		public virtual void testSignatureParsingSHA512()
		{
			XMSSParameters @params = new XMSSParameters(10, new SHA512Digest());
			XMSS xmss = new XMSS(@params, new NullPRNG());
			xmss.generateKeys();
			byte[] message = new byte[1024];
			byte[] sig1 = xmss.sign(message);
			XMSSSignature sig2 = (new XMSSSignature.Builder(@params)).withSignature(sig1).build();

			byte[] sig3 = sig2.toByteArray();
			assertEquals(true, Arrays.areEqual(sig1, sig3));
		}

		public virtual void testConstructor()
		{
			XMSSParameters @params = new XMSSParameters(10, new SHA256Digest());
			XMSSSignature sig = (new XMSSSignature.Builder(@params)).build();

			byte[] sigByte = sig.toByteArray();
			/* check everything is 0 */
			for (int i = 0; i < sigByte.Length; i++)
			{
				assertEquals(0x00, sigByte[i]);
			}
		}
	}

}