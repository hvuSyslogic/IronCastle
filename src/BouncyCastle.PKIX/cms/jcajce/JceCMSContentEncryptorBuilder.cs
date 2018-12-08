using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.oiw;

namespace org.bouncycastle.cms.jcajce
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DefaultSecretKeySizeProvider = org.bouncycastle.@operator.DefaultSecretKeySizeProvider;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;
	using SecretKeySizeProvider = org.bouncycastle.@operator.SecretKeySizeProvider;
	using JceGenericKey = org.bouncycastle.@operator.jcajce.JceGenericKey;

	/// <summary>
	/// Builder for the content encryptor in EnvelopedData - used to encrypt the actual transmitted content.
	/// </summary>
	public class JceCMSContentEncryptorBuilder
	{
		private static readonly SecretKeySizeProvider KEY_SIZE_PROVIDER = DefaultSecretKeySizeProvider.INSTANCE;


		private readonly ASN1ObjectIdentifier encryptionOID;
		private readonly int keySize;

		private EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
		private SecureRandom random;
		private AlgorithmParameters algorithmParameters;

		public JceCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID) : this(encryptionOID, KEY_SIZE_PROVIDER.getKeySize(encryptionOID))
		{
		}

		public JceCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID, int keySize)
		{
			this.encryptionOID = encryptionOID;

			int fixedSize = KEY_SIZE_PROVIDER.getKeySize(encryptionOID);

			if (encryptionOID.Equals(PKCSObjectIdentifiers_Fields.des_EDE3_CBC))
			{
				if (keySize != 168 && keySize != fixedSize)
				{
					throw new IllegalArgumentException("incorrect keySize for encryptionOID passed to builder.");
				}
				this.keySize = 168;
			}
			else if (encryptionOID.Equals(OIWObjectIdentifiers_Fields.desCBC))
			{
				if (keySize != 56 && keySize != fixedSize)
				{
					throw new IllegalArgumentException("incorrect keySize for encryptionOID passed to builder.");
				}
				this.keySize = 56;
			}
			else
			{
				if (fixedSize > 0 && fixedSize != keySize)
				{
					throw new IllegalArgumentException("incorrect keySize for encryptionOID passed to builder.");
				}
				this.keySize = keySize;
			}
		}

		/// <summary>
		/// Set the provider to use for content encryption.
		/// </summary>
		/// <param name="provider"> the provider object to use for cipher and default parameters creation. </param>
		/// <returns> the current builder instance. </returns>
		public virtual JceCMSContentEncryptorBuilder setProvider(Provider provider)
		{
			this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));

			return this;
		}

		/// <summary>
		/// Set the provider to use for content encryption (by name)
		/// </summary>
		/// <param name="providerName"> the name of the provider to use for cipher and default parameters creation. </param>
		/// <returns> the current builder instance. </returns>
		public virtual JceCMSContentEncryptorBuilder setProvider(string providerName)
		{
			this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));

			return this;
		}

		/// <summary>
		/// Provide a specified source of randomness to be used for session key and IV/nonce generation.
		/// </summary>
		/// <param name="random"> the secure random to use. </param>
		/// <returns> the current builder instance. </returns>
		public virtual JceCMSContentEncryptorBuilder setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		/// <summary>
		/// Provide a set of algorithm parameters for the content encryption cipher to use.
		/// </summary>
		/// <param name="algorithmParameters"> algorithmParameters for content encryption. </param>
		/// <returns> the current builder instance. </returns>
		public virtual JceCMSContentEncryptorBuilder setAlgorithmParameters(AlgorithmParameters algorithmParameters)
		{
			this.algorithmParameters = algorithmParameters;

			return this;
		}

		public virtual OutputEncryptor build()
		{
			return new CMSOutputEncryptor(this, encryptionOID, keySize, algorithmParameters, random);
		}

		public class CMSOutputEncryptor : OutputEncryptor
		{
			private readonly JceCMSContentEncryptorBuilder outerInstance;

			internal SecretKey encKey;
			internal AlgorithmIdentifier algorithmIdentifier;
			internal Cipher cipher;

			public CMSOutputEncryptor(JceCMSContentEncryptorBuilder outerInstance, ASN1ObjectIdentifier encryptionOID, int keySize, AlgorithmParameters @params, SecureRandom random)
			{
				this.outerInstance = outerInstance;
				KeyGenerator keyGen = outerInstance.helper.createKeyGenerator(encryptionOID);

				if (random == null)
				{
					random = new SecureRandom();
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

				if (@params == null)
				{
					@params = outerInstance.helper.generateParameters(encryptionOID, encKey, random);
				}

				try
				{
					cipher.init(Cipher.ENCRYPT_MODE, encKey, @params, random);
				}
				catch (GeneralSecurityException e)
				{
					throw new CMSException("unable to initialize cipher: " + e.Message, e);
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