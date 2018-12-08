namespace org.bouncycastle.pkcs.bc
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PKCS12PBEParams = org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using ExtendedDigest = org.bouncycastle.crypto.ExtendedDigest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using PKCS12ParametersGenerator = org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
	using CipherOutputStream = org.bouncycastle.crypto.io.CipherOutputStream;
	using PKCS7Padding = org.bouncycastle.crypto.paddings.PKCS7Padding;
	using PaddedBufferedBlockCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;

	public class BcPKCS12PBEOutputEncryptorBuilder
	{
		private ExtendedDigest digest;

		private BufferedBlockCipher engine;
		private ASN1ObjectIdentifier algorithm;
		private SecureRandom random;
		private int iterationCount = 1024;

		public BcPKCS12PBEOutputEncryptorBuilder(ASN1ObjectIdentifier algorithm, BlockCipher engine) : this(algorithm, engine, new SHA1Digest())
		{
		}

		public BcPKCS12PBEOutputEncryptorBuilder(ASN1ObjectIdentifier algorithm, BlockCipher engine, ExtendedDigest pbeDigest)
		{
			this.algorithm = algorithm;
			this.engine = new PaddedBufferedBlockCipher(engine, new PKCS7Padding());
			this.digest = pbeDigest;
		}

		public virtual BcPKCS12PBEOutputEncryptorBuilder setIterationCount(int iterationCount)
		{
			this.iterationCount = iterationCount;
			return this;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.OutputEncryptor build(final char[] password)
		public virtual OutputEncryptor build(char[] password)
		{
			if (random == null)
			{
				random = new SecureRandom();
			}

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] salt = new byte[20];
			byte[] salt = new byte[20];

			random.nextBytes(salt);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.pkcs.PKCS12PBEParams pbeParams = new org.bouncycastle.asn1.pkcs.PKCS12PBEParams(salt, iterationCount);
			PKCS12PBEParams pbeParams = new PKCS12PBEParams(salt, iterationCount);

			CipherParameters @params = PKCS12PBEUtils.createCipherParameters(algorithm, digest, engine.getBlockSize(), pbeParams, password);

			engine.init(true, @params);

			return new OutputEncryptorAnonymousInnerClass(this, password, pbeParams);
		}

		public class OutputEncryptorAnonymousInnerClass : OutputEncryptor
		{
			private readonly BcPKCS12PBEOutputEncryptorBuilder outerInstance;

			private char[] password;
			private PKCS12PBEParams pbeParams;

			public OutputEncryptorAnonymousInnerClass(BcPKCS12PBEOutputEncryptorBuilder outerInstance, char[] password, PKCS12PBEParams pbeParams)
			{
				this.outerInstance = outerInstance;
				this.password = password;
				this.pbeParams = pbeParams;
			}

			public AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return new AlgorithmIdentifier(outerInstance.algorithm, pbeParams);
			}

			public OutputStream getOutputStream(OutputStream @out)
			{
				return new CipherOutputStream(@out, outerInstance.engine);
			}

			public GenericKey getKey()
			{
				return new GenericKey(new AlgorithmIdentifier(outerInstance.algorithm, pbeParams), PKCS12ParametersGenerator.PKCS12PasswordToBytes(password));
			}
		}
	}

}