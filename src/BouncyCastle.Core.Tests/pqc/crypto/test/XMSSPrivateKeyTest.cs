namespace org.bouncycastle.pqc.crypto.test
{

	using TestCase = junit.framework.TestCase;
	using Digest = org.bouncycastle.crypto.Digest;
	using Xof = org.bouncycastle.crypto.Xof;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using SHAKEDigest = org.bouncycastle.crypto.digests.SHAKEDigest;
	using XMSSParameters = org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
	using XMSSPrivateKeyParameters = org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Test cases for XMSSPrivateKey class.
	/// </summary>
	public class XMSSPrivateKeyTest : TestCase
	{
		public virtual void testPrivateKeyParsing()
		{
			parsingTest(new SHA256Digest());
			parsingTest(new SHA512Digest());
			parsingTest(new SHAKEDigest(128));
			parsingTest(new SHAKEDigest(256));
		}

		private void parsingTest(Digest digest)
		{
				XMSSParameters @params = new XMSSParameters(10, digest);
				byte[] root = generateRoot(digest);
				XMSSPrivateKeyParameters privateKey = (new XMSSPrivateKeyParameters.Builder(@params)).withRoot(root).build();

				byte[] export = privateKey.toByteArray();

				XMSSPrivateKeyParameters privateKey2 = (new XMSSPrivateKeyParameters.Builder(@params)).withPrivateKey(export, @params).build();

				assertEquals(privateKey.getIndex(), privateKey2.getIndex());
				assertEquals(true, Arrays.areEqual(privateKey.getSecretKeySeed(), privateKey2.getSecretKeySeed()));
				assertEquals(true, Arrays.areEqual(privateKey.getSecretKeyPRF(), privateKey2.getSecretKeyPRF()));
				assertEquals(true, Arrays.areEqual(privateKey.getPublicSeed(), privateKey2.getPublicSeed()));
				assertEquals(true, Arrays.areEqual(privateKey.getRoot(), privateKey2.getRoot()));
		}

		private byte[] generateRoot(Digest digest)
		{
			int digestSize = (digest is Xof) ? digest.getDigestSize() * 2 : digest.getDigestSize();
			byte[] rv = new byte[digestSize];

			for (int i = 0; i != rv.Length; i++)
			{
				rv[i] = (byte)i;
			}

			return rv;
		}

	}

}