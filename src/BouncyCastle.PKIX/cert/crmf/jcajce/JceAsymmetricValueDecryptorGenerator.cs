namespace org.bouncycastle.cert.crmf.jcajce
{


	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using InputDecryptor = org.bouncycastle.@operator.InputDecryptor;
	using OperatorException = org.bouncycastle.@operator.OperatorException;
	using JceAsymmetricKeyUnwrapper = org.bouncycastle.@operator.jcajce.JceAsymmetricKeyUnwrapper;

	public class JceAsymmetricValueDecryptorGenerator : ValueDecryptorGenerator
	{
		private PrivateKey recipientKey;
		private CRMFHelper helper = new CRMFHelper(new DefaultJcaJceHelper());
		private Provider provider = null;
		private string providerName = null;

		public JceAsymmetricValueDecryptorGenerator(PrivateKey recipientKey)
		{
			this.recipientKey = recipientKey;
		}

		public virtual JceAsymmetricValueDecryptorGenerator setProvider(Provider provider)
		{
			this.helper = new CRMFHelper(new ProviderJcaJceHelper(provider));
			this.provider = provider;
			this.providerName = null;

			return this;
		}

		public virtual JceAsymmetricValueDecryptorGenerator setProvider(string providerName)
		{
			this.helper = new CRMFHelper(new NamedJcaJceHelper(providerName));
			this.provider = null;
			this.providerName = providerName;

			return this;
		}

		private Key extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
		{
			try
			{
				JceAsymmetricKeyUnwrapper unwrapper = new JceAsymmetricKeyUnwrapper(keyEncryptionAlgorithm, recipientKey);
				if (provider != null)
				{
					unwrapper.setProvider(provider);
				}
				if (!string.ReferenceEquals(providerName, null))
				{
					unwrapper.setProvider(providerName);
				}

				return new SecretKeySpec((byte[])unwrapper.generateUnwrappedKey(contentEncryptionAlgorithm, encryptedContentEncryptionKey).getRepresentation(), contentEncryptionAlgorithm.getAlgorithm().getId());
			}
			catch (OperatorException e)
			{
				throw new CRMFException("key invalid in message: " + e.Message, e);
			}
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.InputDecryptor getValueDecryptor(org.bouncycastle.asn1.x509.AlgorithmIdentifier keyEncryptionAlgorithm, final org.bouncycastle.asn1.x509.AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey) throws org.bouncycastle.cert.crmf.CRMFException
		public virtual InputDecryptor getValueDecryptor(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
		{
			Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, encryptedContentEncryptionKey);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.Cipher dataCipher = helper.createContentCipher(secretKey, contentEncryptionAlgorithm);
			Cipher dataCipher = helper.createContentCipher(secretKey, contentEncryptionAlgorithm);

			return new InputDecryptorAnonymousInnerClass(this, contentEncryptionAlgorithm, dataCipher);
		}

		public class InputDecryptorAnonymousInnerClass : InputDecryptor
		{
			private readonly JceAsymmetricValueDecryptorGenerator outerInstance;

			private AlgorithmIdentifier contentEncryptionAlgorithm;
			private Cipher dataCipher;

			public InputDecryptorAnonymousInnerClass(JceAsymmetricValueDecryptorGenerator outerInstance, AlgorithmIdentifier contentEncryptionAlgorithm, Cipher dataCipher)
			{
				this.outerInstance = outerInstance;
				this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
				this.dataCipher = dataCipher;
			}

			public AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return contentEncryptionAlgorithm;
			}

			public InputStream getInputStream(InputStream dataIn)
			{
				return new CipherInputStream(dataIn, dataCipher);
			}
		}
	}

}