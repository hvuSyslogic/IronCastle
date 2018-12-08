namespace org.bouncycastle.@operator.jcajce
{


	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JceSymmetricKeyUnwrapper : SymmetricKeyUnwrapper
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private SecretKey secretKey;

		public JceSymmetricKeyUnwrapper(AlgorithmIdentifier algorithmIdentifier, SecretKey secretKey) : base(algorithmIdentifier)
		{

			this.secretKey = secretKey;
		}

		public virtual JceSymmetricKeyUnwrapper setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		public virtual JceSymmetricKeyUnwrapper setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		public override GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedKey)
		{
			try
			{
				Cipher keyCipher = helper.createSymmetricWrapper(this.getAlgorithmIdentifier().getAlgorithm());

				keyCipher.init(Cipher.UNWRAP_MODE, secretKey);

				return new JceGenericKey(encryptedKeyAlgorithm, keyCipher.unwrap(encryptedKey, helper.getKeyAlgorithmName(encryptedKeyAlgorithm.getAlgorithm()), Cipher.SECRET_KEY));
			}
			catch (InvalidKeyException e)
			{
				throw new OperatorException("key invalid in message.", e);
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new OperatorException("can't find algorithm.", e);
			}
		}
	}

}