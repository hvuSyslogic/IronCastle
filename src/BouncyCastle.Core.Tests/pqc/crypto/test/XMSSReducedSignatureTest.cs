namespace org.bouncycastle.pqc.crypto.test
{
	using TestCase = junit.framework.TestCase;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using XMSSMT = org.bouncycastle.pqc.crypto.xmss.XMSSMT;
	using XMSSMTParameters = org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
	using XMSSMTSignature = org.bouncycastle.pqc.crypto.xmss.XMSSMTSignature;
	using XMSSParameters = org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
	using XMSSReducedSignature = org.bouncycastle.pqc.crypto.xmss.XMSSReducedSignature;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Test cases for XMSSReducedSignature class.
	/// </summary>
	public class XMSSReducedSignatureTest : TestCase
	{

		public virtual void testSignatureParsingSHA256()
		{
			XMSSMTParameters @params = new XMSSMTParameters(8, 2, new SHA256Digest());
			XMSSMT mt = new XMSSMT(@params, new NullPRNG());
			mt.generateKeys();
			byte[] message = new byte[1024];
			byte[] sig1 = mt.sign(message);
			XMSSMTSignature sig2 = (new XMSSMTSignature.Builder(@params)).withSignature(sig1).build();

			XMSSReducedSignature reducedSignature1 = sig2.getReducedSignatures().get(0);
			byte[] reducedSignatureBinary = reducedSignature1.toByteArray();
			XMSSReducedSignature reducedSignature2 = (new XMSSReducedSignature.Builder(new XMSSParameters(4, new SHA256Digest()))).withReducedSignature(reducedSignatureBinary).build();

			assertTrue(Arrays.areEqual(reducedSignatureBinary, reducedSignature2.toByteArray()));
		}

		public virtual void testSignatureParsingSHA512()
		{
			XMSSMTParameters @params = new XMSSMTParameters(4, 2, new SHA512Digest());
			XMSSMT mt = new XMSSMT(@params, new NullPRNG());
			mt.generateKeys();
			byte[] message = new byte[1024];
			byte[] sig1 = mt.sign(message);
			XMSSMTSignature sig2 = (new XMSSMTSignature.Builder(@params)).withSignature(sig1).build();

			XMSSReducedSignature reducedSignature1 = sig2.getReducedSignatures().get(0);
			byte[] reducedSignatureBinary = reducedSignature1.toByteArray();
			XMSSReducedSignature reducedSignature2 = (new XMSSReducedSignature.Builder(new XMSSParameters(2, new SHA512Digest()))).withReducedSignature(reducedSignatureBinary).build();

			assertTrue(Arrays.areEqual(reducedSignatureBinary, reducedSignature2.toByteArray()));
		}

		public virtual void testConstructor()
		{
			XMSSReducedSignature sig = (new XMSSReducedSignature.Builder(new XMSSParameters(4, new SHA512Digest()))).build();

			byte[] sigByte = sig.toByteArray();
			/* check everything is 0 */
			for (int i = 0; i < sigByte.Length; i++)
			{
				assertEquals(0x00, sigByte[i]);
			}
		}
	}

}