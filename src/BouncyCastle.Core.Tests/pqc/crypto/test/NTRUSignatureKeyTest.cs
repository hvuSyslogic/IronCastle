namespace org.bouncycastle.pqc.crypto.test
{

	using TestCase = junit.framework.TestCase;
	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using NTRUSigner = org.bouncycastle.pqc.crypto.ntru.NTRUSigner;
	using NTRUSigningKeyGenerationParameters = org.bouncycastle.pqc.crypto.ntru.NTRUSigningKeyGenerationParameters;
	using NTRUSigningKeyPairGenerator = org.bouncycastle.pqc.crypto.ntru.NTRUSigningKeyPairGenerator;
	using NTRUSigningPrivateKeyParameters = org.bouncycastle.pqc.crypto.ntru.NTRUSigningPrivateKeyParameters;
	using NTRUSigningPublicKeyParameters = org.bouncycastle.pqc.crypto.ntru.NTRUSigningPublicKeyParameters;

	public class NTRUSignatureKeyTest : TestCase
	{
		public virtual void testEncode()
		{
			foreach (NTRUSigningKeyGenerationParameters @params in new NTRUSigningKeyGenerationParameters[]{NTRUSigningKeyGenerationParameters.TEST157, NTRUSigningKeyGenerationParameters.TEST157_PROD})
			{
				testEncode(@params);
			}
		}

		private void testEncode(NTRUSigningKeyGenerationParameters @params)
		{
			NTRUSigner ntru = new NTRUSigner(@params.getSigningParameters());
			NTRUSigningKeyPairGenerator kGen = new NTRUSigningKeyPairGenerator();

			kGen.init(@params);

			AsymmetricCipherKeyPair kp = kGen.generateKeyPair();

			NTRUSigningPrivateKeyParameters kPriv = (NTRUSigningPrivateKeyParameters)kp.getPrivate();
			NTRUSigningPublicKeyParameters kPub = (NTRUSigningPublicKeyParameters)kp.getPublic();

			// encode to byte[] and reconstruct
			byte[] priv = kPriv.getEncoded();
			byte[] pub = kPub.getEncoded();
			AsymmetricCipherKeyPair kp2 = new AsymmetricCipherKeyPair(new NTRUSigningPublicKeyParameters(pub, @params.getSigningParameters()), new NTRUSigningPrivateKeyParameters(priv, @params));
			assertEquals(kPub, kp2.getPublic());
			assertEquals(kPriv, kp2.getPrivate());

			// encode to OutputStream and reconstruct
			ByteArrayOutputStream bos1 = new ByteArrayOutputStream();
			ByteArrayOutputStream bos2 = new ByteArrayOutputStream();
			kPriv.writeTo(bos1);
			kPub.writeTo(bos2);
			ByteArrayInputStream bis1 = new ByteArrayInputStream(bos1.toByteArray());
			ByteArrayInputStream bis2 = new ByteArrayInputStream(bos2.toByteArray());
			AsymmetricCipherKeyPair kp3 = new AsymmetricCipherKeyPair(new NTRUSigningPublicKeyParameters(bis2, @params.getSigningParameters()), new NTRUSigningPrivateKeyParameters(bis1, @params));
			assertEquals(kPub, kp3.getPublic());
			assertEquals(kPriv, kp3.getPrivate());
		}
	}

}