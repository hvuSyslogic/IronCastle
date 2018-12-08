namespace org.bouncycastle.jcajce.util
{


	/// <summary>
	/// <seealso cref="JcaJceHelper"/> that obtains all algorithms using the default JCA/JCE mechanism (i.e.
	/// without specifying a provider).
	/// </summary>
	public class DefaultJcaJceHelper : JcaJceHelper
	{
		public virtual Cipher createCipher(string algorithm)
		{
			return Cipher.getInstance(algorithm);
		}

		public virtual Mac createMac(string algorithm)
		{
			return Mac.getInstance(algorithm);
		}

		public virtual KeyAgreement createKeyAgreement(string algorithm)
		{
			return KeyAgreement.getInstance(algorithm);
		}

		public virtual AlgorithmParameterGenerator createAlgorithmParameterGenerator(string algorithm)
		{
			return AlgorithmParameterGenerator.getInstance(algorithm);
		}

		public virtual AlgorithmParameters createAlgorithmParameters(string algorithm)
		{
			return AlgorithmParameters.getInstance(algorithm);
		}

		public virtual KeyGenerator createKeyGenerator(string algorithm)
		{
			return KeyGenerator.getInstance(algorithm);
		}

		public virtual KeyFactory createKeyFactory(string algorithm)
		{
			return KeyFactory.getInstance(algorithm);
		}

		public virtual SecretKeyFactory createSecretKeyFactory(string algorithm)
		{
			return SecretKeyFactory.getInstance(algorithm);
		}

		public virtual KeyPairGenerator createKeyPairGenerator(string algorithm)
		{
			return KeyPairGenerator.getInstance(algorithm);
		}

		public virtual MessageDigest createDigest(string algorithm)
		{
			return MessageDigest.getInstance(algorithm);
		}

		public virtual Signature createSignature(string algorithm)
		{
			return Signature.getInstance(algorithm);
		}

		public virtual CertificateFactory createCertificateFactory(string algorithm)
		{
			return CertificateFactory.getInstance(algorithm);
		}

		public virtual SecureRandom createSecureRandom(string algorithm)
		{
			return SecureRandom.getInstance(algorithm);
		}
	}

}