namespace org.bouncycastle.cert.crmf.jcajce
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using DefaultSecretKeySizeProvider = org.bouncycastle.@operator.DefaultSecretKeySizeProvider;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;
	using SecretKeySizeProvider = org.bouncycastle.@operator.SecretKeySizeProvider;
	using JceGenericKey = org.bouncycastle.@operator.jcajce.JceGenericKey;

	public class JceCRMFEncryptorBuilder
	{
		private static readonly SecretKeySizeProvider KEY_SIZE_PROVIDER = DefaultSecretKeySizeProvider.INSTANCE;

		private readonly ASN1ObjectIdentifier encryptionOID;
		private readonly int keySize;

		private CRMFHelper helper = new CRMFHelper(new DefaultJcaJceHelper());
		private SecureRandom random;

		public JceCRMFEncryptorBuilder(ASN1ObjectIdentifier encryptionOID) : this(encryptionOID, -1)
		{
		}

		public JceCRMFEncryptorBuilder(ASN1ObjectIdentifier encryptionOID, int keySize)
		{
			this.encryptionOID = encryptionOID;
			this.keySize = keySize;
		}

		public virtual JceCRMFEncryptorBuilder setProvider(Provider provider)
		{
			this.helper = new CRMFHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		public virtual JceCRMFEncryptorBuilder setProvider(string providerName)
		{
			this.helper = new CRMFHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		public virtual JceCRMFEncryptorBuilder setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public virtual OutputEncryptor build()
		{
			return new CRMFOutputEncryptor(this, encryptionOID, keySize, random);
		}

		public class CRMFOutputEncryptor : OutputEncryptor
		{
			private readonly JceCRMFEncryptorBuilder outerInstance;

			internal SecretKey encKey;
			internal AlgorithmIdentifier algorithmIdentifier;
			internal Cipher cipher;

			public CRMFOutputEncryptor(JceCRMFEncryptorBuilder outerInstance, ASN1ObjectIdentifier encryptionOID, int keySize, SecureRandom random)
			{
				this.outerInstance = outerInstance;
				KeyGenerator keyGen = outerInstance.helper.createKeyGenerator(encryptionOID);

				if (random == null)
				{
					random = new SecureRandom();
				}

				if (keySize < 0)
				{
					keySize = KEY_SIZE_PROVIDER.getKeySize(encryptionOID);
				}

				if (keySize < 0)
				{
					keyGen.init(random);
				}
				else
				{
					keyGen.init(keySize, random);
				}

				cipher = outerInstance.helper.createCipher(encryptionOID);
				encKey = keyGen.generateKey();
				AlgorithmParameters @params = outerInstance.helper.generateParameters(encryptionOID, encKey, random);

				try
				{
					cipher.init(Cipher.ENCRYPT_MODE, encKey, @params, random);
				}
				catch (GeneralSecurityException e)
				{
					throw new CRMFException("unable to initialize cipher: " + e.Message, e);
				}

				//
				// If params are null we try and second guess on them as some providers don't provide
				// algorithm parameter generation explicity but instead generate them under the hood.
				//
				if (@params == null)
				{
					@params = cipher.getParameters();
				}

				algorithmIdentifier = outerInstance.helper.getAlgorithmIdentifier(encryptionOID, @params);
			}

			public virtual AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return algorithmIdentifier;
			}

			public virtual OutputStream getOutputStream(OutputStream dOut)
			{
				return new CipherOutputStream(dOut, cipher);
			}

			public virtual GenericKey getKey()
			{
				return new JceGenericKey(algorithmIdentifier, encKey);
			}
		}
	}

}