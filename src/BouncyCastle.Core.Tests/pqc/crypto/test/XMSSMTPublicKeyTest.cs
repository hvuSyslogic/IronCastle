namespace org.bouncycastle.pqc.crypto.test
{

	using TestCase = junit.framework.TestCase;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using XMSSMT = org.bouncycastle.pqc.crypto.xmss.XMSSMT;
	using XMSSMTParameters = org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
	using XMSSMTPublicKeyParameters = org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Test cases for XMSSMTPublicKey class.
	/// 
	/// </summary>
	public class XMSSMTPublicKeyTest : TestCase
	{

		public virtual void testPublicKeyParsingSHA256()
		{
			XMSSMTParameters @params = new XMSSMTParameters(20, 10, new SHA256Digest());
			XMSSMT mt = new XMSSMT(@params, new SecureRandom());
			mt.generateKeys();
			byte[] privateKey = mt.exportPrivateKey();
			byte[] publicKey = mt.exportPublicKey();

			mt.importState(privateKey, publicKey);

			assertTrue(Arrays.areEqual(publicKey, mt.exportPublicKey()));
		}

		public virtual void testConstructor()
		{
			XMSSMTParameters @params = new XMSSMTParameters(20, 10, new SHA256Digest());
			XMSSMTPublicKeyParameters pk = (new XMSSMTPublicKeyParameters.Builder(@params)).build();

			byte[] pkByte = pk.toByteArray();
			/* check everything is 0 */
			for (int i = 0; i < pkByte.Length; i++)
			{
				assertEquals(0x00, pkByte[i]);
			}
		}
	}

}