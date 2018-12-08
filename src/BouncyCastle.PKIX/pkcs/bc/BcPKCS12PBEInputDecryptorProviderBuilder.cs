namespace org.bouncycastle.pkcs.bc
{

	using PKCS12PBEParams = org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using ExtendedDigest = org.bouncycastle.crypto.ExtendedDigest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using PKCS12ParametersGenerator = org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
	using CipherInputStream = org.bouncycastle.crypto.io.CipherInputStream;
	using PaddedBufferedBlockCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using InputDecryptor = org.bouncycastle.@operator.InputDecryptor;
	using InputDecryptorProvider = org.bouncycastle.@operator.InputDecryptorProvider;

	public class BcPKCS12PBEInputDecryptorProviderBuilder
	{
		private ExtendedDigest digest;

		public BcPKCS12PBEInputDecryptorProviderBuilder() : this(new SHA1Digest())
		{
		}

		public BcPKCS12PBEInputDecryptorProviderBuilder(ExtendedDigest digest)
		{
			 this.digest = digest;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.InputDecryptorProvider build(final char[] password)
		public virtual InputDecryptorProvider build(char[] password)
		{
			return new InputDecryptorProviderAnonymousInnerClass(this, password);

		}

		public class InputDecryptorProviderAnonymousInnerClass : InputDecryptorProvider
		{
			private readonly BcPKCS12PBEInputDecryptorProviderBuilder outerInstance;

			private char[] password;

			public InputDecryptorProviderAnonymousInnerClass(BcPKCS12PBEInputDecryptorProviderBuilder outerInstance, char[] password)
			{
				this.outerInstance = outerInstance;
				this.password = password;
			}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.InputDecryptor get(final org.bouncycastle.asn1.x509.AlgorithmIdentifier algorithmIdentifier)
			public InputDecryptor get(AlgorithmIdentifier algorithmIdentifier)
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher engine = PKCS12PBEUtils.getEngine(algorithmIdentifier.getAlgorithm());
				PaddedBufferedBlockCipher engine = PKCS12PBEUtils.getEngine(algorithmIdentifier.getAlgorithm());

				PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());

				CipherParameters @params = PKCS12PBEUtils.createCipherParameters(algorithmIdentifier.getAlgorithm(), outerInstance.digest, engine.getBlockSize(), pbeParams, password);

				engine.init(false, @params);

				return new InputDecryptorAnonymousInnerClass(this, algorithmIdentifier, engine);
			}

			public class InputDecryptorAnonymousInnerClass : InputDecryptor
			{
				private readonly InputDecryptorProviderAnonymousInnerClass outerInstance;

				private AlgorithmIdentifier algorithmIdentifier;
				private PaddedBufferedBlockCipher engine;

				public InputDecryptorAnonymousInnerClass(InputDecryptorProviderAnonymousInnerClass outerInstance, AlgorithmIdentifier algorithmIdentifier, PaddedBufferedBlockCipher engine)
				{
					this.outerInstance = outerInstance;
					this.algorithmIdentifier = algorithmIdentifier;
					this.engine = engine;
				}

				public AlgorithmIdentifier getAlgorithmIdentifier()
				{
					return algorithmIdentifier;
				}

				public InputStream getInputStream(InputStream input)
				{
					return new CipherInputStream(input, engine);
				}

				public GenericKey getKey()
				{
					return new GenericKey(PKCS12ParametersGenerator.PKCS12PasswordToBytes(outerInstance.password));
				}
			}
		}
	}

}