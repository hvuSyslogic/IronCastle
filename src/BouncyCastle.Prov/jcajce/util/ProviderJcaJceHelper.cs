namespace org.bouncycastle.jcajce.util
{


	/// <summary>
	/// <seealso cref="JcaJceHelper"/> that obtains all algorithms from a specific <seealso cref="Provider"/> instance.
	/// </summary>
	public class ProviderJcaJceHelper : JcaJceHelper
	{
		protected internal readonly Provider provider;

		public ProviderJcaJceHelper(Provider provider)
		{
			this.provider = provider;
		}

		public virtual Cipher createCipher(string algorithm)
		{
			return Cipher.getInstance(algorithm, provider);
		}

		public virtual Mac createMac(string algorithm)
		{
			return Mac.getInstance(algorithm, provider);
		}

		public virtual KeyAgreement createKeyAgreement(string algorithm)
		{
			return KeyAgreement.getInstance(algorithm, provider);
		}

		public virtual AlgorithmParameterGenerator createAlgorithmParameterGenerator(string algorithm)
		{
			return AlgorithmParameterGenerator.getInstance(algorithm, provider);
		}

		public virtual AlgorithmParameters createAlgorithmParameters(string algorithm)
		{
			return AlgorithmParameters.getInstance(algorithm, provider);
		}

		public virtual KeyGenerator createKeyGenerator(string algorithm)
		{
			return KeyGenerator.getInstance(algorithm, provider);
		}

		public virtual KeyFactory createKeyFactory(string algorithm)
		{
			return KeyFactory.getInstance(algorithm, provider);
		}

		public virtual SecretKeyFactory createSecretKeyFactory(string algorithm)
		{
			return SecretKeyFactory.getInstance(algorithm, provider);
		}

		public virtual KeyPairGenerator createKeyPairGenerator(string algorithm)
		{
			return KeyPairGenerator.getInstance(algorithm, provider);
		}

		public virtual MessageDigest createDigest(string algorithm)
		{
			return MessageDigest.getInstance(algorithm, provider);
		}

		public virtual Signature createSignature(string algorithm)
		{
			return Signature.getInstance(algorithm, provider);
		}

		public virtual CertificateFactory createCertificateFactory(string algorithm)
		{
			return CertificateFactory.getInstance(algorithm, provider);
		}

		public virtual SecureRandom createSecureRandom(string algorithm)
		{
			return SecureRandom.getInstance(algorithm, provider);
		}
	}

}