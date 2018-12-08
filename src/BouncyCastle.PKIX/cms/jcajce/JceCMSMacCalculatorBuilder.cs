namespace org.bouncycastle.cms.jcajce
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using MacOutputStream = org.bouncycastle.jcajce.io.MacOutputStream;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;
	using JceGenericKey = org.bouncycastle.@operator.jcajce.JceGenericKey;

	public class JceCMSMacCalculatorBuilder
	{
		private readonly ASN1ObjectIdentifier macOID;
		private readonly int keySize;

		private EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
		private AlgorithmParameters algorithmParameters;
		private SecureRandom random;

		public JceCMSMacCalculatorBuilder(ASN1ObjectIdentifier macOID) : this(macOID, -1)
		{
		}

		public JceCMSMacCalculatorBuilder(ASN1ObjectIdentifier macOID, int keySize)
		{
			this.macOID = macOID;
			this.keySize = keySize;
		}

		/// <summary>
		/// Set the provider to use for content encryption.
		/// </summary>
		/// <param name="provider"> the provider object to use for MAC and default parameters creation. </param>
		/// <returns> the current builder instance. </returns>
		public virtual JceCMSMacCalculatorBuilder setProvider(Provider provider)
		{
			this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));

			return this;
		}

		/// <summary>
		/// Set the provider to use for content encryption (by name)
		/// </summary>
		/// <param name="providerName"> the name of the provider to use for MAC and default parameters creation. </param>
		/// <returns> the current builder instance. </returns>
		public virtual JceCMSMacCalculatorBuilder setProvider(string providerName)
		{
			this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));

			return this;
		}

		/// <summary>
		/// Provide a specified source of randomness to be used for session key and IV/nonce generation.
		/// </summary>
		/// <param name="random"> the secure random to use. </param>
		/// <returns> the current builder instance. </returns>
		public virtual JceCMSMacCalculatorBuilder setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		/// <summary>
		/// Provide a set of algorithm parameters for the content MAC calculator to use.
		/// </summary>
		/// <param name="algorithmParameters"> algorithmParameters for MAC initialisation. </param>
		/// <returns> the current builder instance. </returns>
		public virtual JceCMSMacCalculatorBuilder setAlgorithmParameters(AlgorithmParameters algorithmParameters)
		{
			this.algorithmParameters = algorithmParameters;

			return this;
		}

		public virtual MacCalculator build()
		{
			return new CMSMacCalculator(this, macOID, keySize, algorithmParameters, random);
		}

		public class CMSMacCalculator : MacCalculator
		{
			private readonly JceCMSMacCalculatorBuilder outerInstance;

			internal SecretKey encKey;
			internal AlgorithmIdentifier algorithmIdentifier;
			internal Mac mac;

			public CMSMacCalculator(JceCMSMacCalculatorBuilder outerInstance, ASN1ObjectIdentifier macOID, int keySize, AlgorithmParameters @params, SecureRandom random)
			{
				this.outerInstance = outerInstance;
				KeyGenerator keyGen = outerInstance.helper.createKeyGenerator(macOID);

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

				encKey = keyGen.generateKey();

				if (@params == null)
				{
					@params = outerInstance.helper.generateParameters(macOID, encKey, random);
				}

				algorithmIdentifier = outerInstance.helper.getAlgorithmIdentifier(macOID, @params);
				mac = outerInstance.helper.createContentMac(encKey, algorithmIdentifier);
			}

			public virtual AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return algorithmIdentifier;
			}

			public virtual OutputStream getOutputStream()
			{
				return new MacOutputStream(mac);
			}

			public virtual byte[] getMac()
			{
				return mac.doFinal();
			}

			public virtual GenericKey getKey()
			{
				return new JceGenericKey(algorithmIdentifier, encKey);
			}
		}
	}

}