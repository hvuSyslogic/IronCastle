namespace org.bouncycastle.openpgp.@operator.jcajce
{

	using OutputStreamFactory = org.bouncycastle.jcajce.io.OutputStreamFactory;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JcaPGPContentVerifierBuilderProvider : PGPContentVerifierBuilderProvider
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();

		public JcaPGPContentVerifierBuilderProvider()
		{
		}

		public virtual JcaPGPContentVerifierBuilderProvider setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));
			keyConverter.setProvider(provider);

			return this;
		}

		public virtual JcaPGPContentVerifierBuilderProvider setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
			keyConverter.setProvider(providerName);

			return this;
		}

		public virtual PGPContentVerifierBuilder get(int keyAlgorithm, int hashAlgorithm)
		{
			return new JcaPGPContentVerifierBuilder(this, keyAlgorithm, hashAlgorithm);
		}

		public class JcaPGPContentVerifierBuilder : PGPContentVerifierBuilder
		{
			private readonly JcaPGPContentVerifierBuilderProvider outerInstance;

			internal int hashAlgorithm;
			internal int keyAlgorithm;

			public JcaPGPContentVerifierBuilder(JcaPGPContentVerifierBuilderProvider outerInstance, int keyAlgorithm, int hashAlgorithm)
			{
				this.outerInstance = outerInstance;
				this.keyAlgorithm = keyAlgorithm;
				this.hashAlgorithm = hashAlgorithm;
			}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.openpgp.operator.PGPContentVerifier build(final org.bouncycastle.openpgp.PGPPublicKey publicKey) throws org.bouncycastle.openpgp.PGPException
			public virtual PGPContentVerifier build(PGPPublicKey publicKey)
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.security.Signature signature = helper.createSignature(keyAlgorithm, hashAlgorithm);
				Signature signature = outerInstance.helper.createSignature(keyAlgorithm, hashAlgorithm);

				try
				{
					signature.initVerify(outerInstance.keyConverter.getPublicKey(publicKey));
				}
				catch (InvalidKeyException e)
				{
					throw new PGPException("invalid key.", e);
				}

				return new PGPContentVerifierAnonymousInnerClass(this, publicKey, signature, e);
			}

			public class PGPContentVerifierAnonymousInnerClass : PGPContentVerifier
			{
				private readonly JcaPGPContentVerifierBuilder outerInstance;

				private PGPPublicKey publicKey;
				private Signature signature;
				private InvalidKeyException e;

				public PGPContentVerifierAnonymousInnerClass(JcaPGPContentVerifierBuilder outerInstance, PGPPublicKey publicKey, Signature signature, InvalidKeyException e)
				{
					this.outerInstance = outerInstance;
					this.publicKey = publicKey;
					this.signature = signature;
					this.e = e;
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
					return publicKey.getKeyID();
				}

				public bool verify(byte[] expected)
				{
					try
					{
						return signature.verify(expected);
					}
					catch (SignatureException e)
					{
						throw new PGPRuntimeOperationException("unable to verify signature: " + e.Message, e);
					}
				}

				public OutputStream getOutputStream()
				{
					return OutputStreamFactory.createStream(signature);
				}
			}
		}
	}

}