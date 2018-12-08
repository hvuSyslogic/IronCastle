namespace org.bouncycastle.openpgp.@operator.jcajce
{

	using OutputStreamFactory = org.bouncycastle.jcajce.io.OutputStreamFactory;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using TeeOutputStream = org.bouncycastle.util.io.TeeOutputStream;

	public class JcaPGPContentSignerBuilder : PGPContentSignerBuilder
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private JcaPGPDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaPGPDigestCalculatorProviderBuilder();
		private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();
		private int hashAlgorithm;
		private SecureRandom random;
		private int keyAlgorithm;

		public JcaPGPContentSignerBuilder(int keyAlgorithm, int hashAlgorithm)
		{
			this.keyAlgorithm = keyAlgorithm;
			this.hashAlgorithm = hashAlgorithm;
		}

		public virtual JcaPGPContentSignerBuilder setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public virtual JcaPGPContentSignerBuilder setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));
			keyConverter.setProvider(provider);
			digestCalculatorProviderBuilder.setProvider(provider);

			return this;
		}

		public virtual JcaPGPContentSignerBuilder setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
			keyConverter.setProvider(providerName);
			digestCalculatorProviderBuilder.setProvider(providerName);

			return this;
		}

		public virtual JcaPGPContentSignerBuilder setDigestProvider(Provider provider)
		{
			digestCalculatorProviderBuilder.setProvider(provider);

			return this;
		}

		public virtual JcaPGPContentSignerBuilder setDigestProvider(string providerName)
		{
			digestCalculatorProviderBuilder.setProvider(providerName);

			return this;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.openpgp.operator.PGPContentSigner build(final int signatureType, org.bouncycastle.openpgp.PGPPrivateKey privateKey) throws org.bouncycastle.openpgp.PGPException
		public virtual PGPContentSigner build(int signatureType, PGPPrivateKey privateKey)
		{
			if (privateKey is JcaPGPPrivateKey)
			{
				return build(signatureType, privateKey.getKeyID(), ((JcaPGPPrivateKey)privateKey).getPrivateKey());
			}
			else
			{
				return build(signatureType, privateKey.getKeyID(), keyConverter.getPrivateKey(privateKey));
			}
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.openpgp.operator.PGPContentSigner build(final int signatureType, final long keyID, final java.security.PrivateKey privateKey) throws org.bouncycastle.openpgp.PGPException
		public virtual PGPContentSigner build(int signatureType, long keyID, PrivateKey privateKey)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.openpgp.operator.PGPDigestCalculator digestCalculator = digestCalculatorProviderBuilder.build().get(hashAlgorithm);
			PGPDigestCalculator digestCalculator = digestCalculatorProviderBuilder.build().get(hashAlgorithm);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.security.Signature signature = helper.createSignature(keyAlgorithm, hashAlgorithm);
			Signature signature = helper.createSignature(keyAlgorithm, hashAlgorithm);

			try
			{
				if (random != null)
				{
					signature.initSign(privateKey, random);
				}
				else
				{
					signature.initSign(privateKey);
				}
			}
			catch (InvalidKeyException e)
			{
			   throw new PGPException("invalid key.", e);
			}

			return new PGPContentSignerAnonymousInnerClass(this, signatureType, keyID, digestCalculator, signature, e);
		}

		public class PGPContentSignerAnonymousInnerClass : PGPContentSigner
		{
			private readonly JcaPGPContentSignerBuilder outerInstance;

			private int signatureType;
			private long keyID;
			private PGPDigestCalculator digestCalculator;
			private Signature signature;
			private InvalidKeyException e;

			public PGPContentSignerAnonymousInnerClass(JcaPGPContentSignerBuilder outerInstance, int signatureType, long keyID, PGPDigestCalculator digestCalculator, Signature signature, InvalidKeyException e)
			{
				this.outerInstance = outerInstance;
				this.signatureType = signatureType;
				this.keyID = keyID;
				this.digestCalculator = digestCalculator;
				this.signature = signature;
				this.e = e;
			}

			public int getType()
			{
				return signatureType;
			}

			public int getHashAlgorithm()
			{
				return outerInstance.hashAlgorithm;
			}

			public int getKeyAlgorithm()
			{
				return outerInstance.keyAlgorithm;
			}

			public long getKeyID()
			{
				return keyID;
			}

			public OutputStream getOutputStream()
			{
				return new TeeOutputStream(OutputStreamFactory.createStream(signature), digestCalculator.getOutputStream());
			}

			public byte[] getSignature()
			{
				try
				{
					return signature.sign();
				}
				catch (SignatureException e)
				{
					throw new PGPRuntimeOperationException("Unable to create signature: " + e.Message, e);
				}
			}

			public byte[] getDigest()
			{
				return digestCalculator.getDigest();
			}
		}
	}

}