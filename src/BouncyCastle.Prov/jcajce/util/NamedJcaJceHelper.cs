namespace org.bouncycastle.jcajce.util
{


	/// <summary>
	/// <seealso cref="JcaJceHelper"/> that obtains all algorithms using a specific named provider.
	/// </summary>
	public class NamedJcaJceHelper : JcaJceHelper
	{
		protected internal readonly string providerName;

		public NamedJcaJceHelper(string providerName)
		{
			this.providerName = providerName;
		}

		public virtual Cipher createCipher(string algorithm)
		{
			return Cipher.getInstance(algorithm, providerName);
		}

		public virtual Mac createMac(string algorithm)
		{
			return Mac.getInstance(algorithm, providerName);
		}

		public virtual KeyAgreement createKeyAgreement(string algorithm)
		{
			return KeyAgreement.getInstance(algorithm, providerName);
		}

		public virtual AlgorithmParameterGenerator createAlgorithmParameterGenerator(string algorithm)
		{
			return AlgorithmParameterGenerator.getInstance(algorithm, providerName);
		}

		public virtual AlgorithmParameters createAlgorithmParameters(string algorithm)
		{
			return AlgorithmParameters.getInstance(algorithm, providerName);
		}

		public virtual KeyGenerator createKeyGenerator(string algorithm)
		{
			return KeyGenerator.getInstance(algorithm, providerName);
		}

		public virtual KeyFactory createKeyFactory(string algorithm)
		{
			return KeyFactory.getInstance(algorithm, providerName);
		}

		public virtual SecretKeyFactory createSecretKeyFactory(string algorithm)
		{
			return SecretKeyFactory.getInstance(algorithm, providerName);
		}

		public virtual KeyPairGenerator createKeyPairGenerator(string algorithm)
		{
			return KeyPairGenerator.getInstance(algorithm, providerName);
		}

		public virtual MessageDigest createDigest(string algorithm)
		{
			return MessageDigest.getInstance(algorithm, providerName);
		}

		public virtual Signature createSignature(string algorithm)
		{
			return Signature.getInstance(algorithm, providerName);
		}

		public virtual CertificateFactory createCertificateFactory(string algorithm)
		{
			return CertificateFactory.getInstance(algorithm, providerName);
		}

		public virtual SecureRandom createSecureRandom(string algorithm)
		{
			return SecureRandom.getInstance(algorithm, providerName);
		}
	}

}