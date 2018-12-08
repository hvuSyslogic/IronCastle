namespace org.bouncycastle.jcajce.util
{


	/// <summary>
	/// Factory interface for instantiating JCA/JCE primitives.
	/// </summary>
	public interface JcaJceHelper
	{
		Cipher createCipher(string algorithm);

		Mac createMac(string algorithm);

		KeyAgreement createKeyAgreement(string algorithm);

		AlgorithmParameterGenerator createAlgorithmParameterGenerator(string algorithm);

		AlgorithmParameters createAlgorithmParameters(string algorithm);

		KeyGenerator createKeyGenerator(string algorithm);

		KeyFactory createKeyFactory(string algorithm);

		SecretKeyFactory createSecretKeyFactory(string algorithm);

		KeyPairGenerator createKeyPairGenerator(string algorithm);

		MessageDigest createDigest(string algorithm);

		Signature createSignature(string algorithm);

		CertificateFactory createCertificateFactory(string algorithm);

		SecureRandom createSecureRandom(string algorithm);
	}

}