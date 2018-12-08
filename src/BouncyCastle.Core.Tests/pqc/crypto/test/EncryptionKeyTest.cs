namespace org.bouncycastle.pqc.crypto.test
{

	using TestCase = junit.framework.TestCase;
	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using NTRUEncryptionKeyGenerationParameters = org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionKeyGenerationParameters;
	using NTRUEncryptionKeyPairGenerator = org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionKeyPairGenerator;
	using NTRUEncryptionPrivateKeyParameters = org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionPrivateKeyParameters;
	using NTRUEncryptionPublicKeyParameters = org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionPublicKeyParameters;

	public class EncryptionKeyTest : TestCase
	{
		public virtual void testEncode()
		{
			foreach (NTRUEncryptionKeyGenerationParameters @params in new NTRUEncryptionKeyGenerationParameters[]{NTRUEncryptionKeyGenerationParameters.APR2011_743, NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST, NTRUEncryptionKeyGenerationParameters.EES1499EP1})
			{
				testEncode(@params);
			}
		}

		private void testEncode(NTRUEncryptionKeyGenerationParameters @params)
		{
			NTRUEncryptionKeyPairGenerator kpGen = new NTRUEncryptionKeyPairGenerator();

			kpGen.init(@params);

			AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
			byte[] priv = ((NTRUEncryptionPrivateKeyParameters)kp.getPrivate()).getEncoded();
			byte[] pub = ((NTRUEncryptionPublicKeyParameters)kp.getPublic()).getEncoded();

			AsymmetricCipherKeyPair kp2 = new AsymmetricCipherKeyPair(new NTRUEncryptionPublicKeyParameters(pub, @params.getEncryptionParameters()), new NTRUEncryptionPrivateKeyParameters(priv, @params.getEncryptionParameters()));
			assertEquals(kp.getPublic(), kp2.getPublic());
			assertEquals(kp.getPrivate(), kp2.getPrivate());

			ByteArrayOutputStream bos1 = new ByteArrayOutputStream();
			ByteArrayOutputStream bos2 = new ByteArrayOutputStream();
			((NTRUEncryptionPrivateKeyParameters)kp.getPrivate()).writeTo(bos1);
			((NTRUEncryptionPublicKeyParameters)kp.getPublic()).writeTo(bos2);
			ByteArrayInputStream bis1 = new ByteArrayInputStream(bos1.toByteArray());
			ByteArrayInputStream bis2 = new ByteArrayInputStream(bos2.toByteArray());
			AsymmetricCipherKeyPair kp3 = new AsymmetricCipherKeyPair(new NTRUEncryptionPublicKeyParameters(bis2, @params.getEncryptionParameters()), new NTRUEncryptionPrivateKeyParameters(bis1, @params.getEncryptionParameters()));
			assertEquals(kp.getPublic(), kp3.getPublic());
			assertEquals(kp.getPrivate(), kp3.getPrivate());
		}
	}

}