namespace org.bouncycastle.openpgp.@operator.bc
{

	using CryptoException = org.bouncycastle.crypto.CryptoException;
	using Signer = org.bouncycastle.crypto.Signer;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using TeeOutputStream = org.bouncycastle.util.io.TeeOutputStream;

	public class BcPGPContentSignerBuilder : PGPContentSignerBuilder
	{
		private BcPGPDigestCalculatorProvider digestCalculatorProvider = new BcPGPDigestCalculatorProvider();
		private BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();
		private int hashAlgorithm;
		private SecureRandom random;
		private int keyAlgorithm;

		public BcPGPContentSignerBuilder(int keyAlgorithm, int hashAlgorithm)
		{
			this.keyAlgorithm = keyAlgorithm;
			this.hashAlgorithm = hashAlgorithm;
		}

		public virtual BcPGPContentSignerBuilder setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.openpgp.operator.PGPContentSigner build(final int signatureType, final org.bouncycastle.openpgp.PGPPrivateKey privateKey) throws org.bouncycastle.openpgp.PGPException
		public virtual PGPContentSigner build(int signatureType, PGPPrivateKey privateKey)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.openpgp.operator.PGPDigestCalculator digestCalculator = digestCalculatorProvider.get(hashAlgorithm);
			PGPDigestCalculator digestCalculator = digestCalculatorProvider.get(hashAlgorithm);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.Signer signer = BcImplProvider.createSigner(keyAlgorithm, hashAlgorithm);
			Signer signer = BcImplProvider.createSigner(keyAlgorithm, hashAlgorithm);

			if (random != null)
			{
				signer.init(true, new ParametersWithRandom(keyConverter.getPrivateKey(privateKey), random));
			}
			else
			{
				signer.init(true, keyConverter.getPrivateKey(privateKey));
			}

			return new PGPContentSignerAnonymousInnerClass(this, signatureType, privateKey, digestCalculator, signer);
		}

		public class PGPContentSignerAnonymousInnerClass : PGPContentSigner
		{
			private readonly BcPGPContentSignerBuilder outerInstance;

			private int signatureType;
			private PGPPrivateKey privateKey;
			private PGPDigestCalculator digestCalculator;
			private Signer signer;

			public PGPContentSignerAnonymousInnerClass(BcPGPContentSignerBuilder outerInstance, int signatureType, PGPPrivateKey privateKey, PGPDigestCalculator digestCalculator, Signer signer)
			{
				this.outerInstance = outerInstance;
				this.signatureType = signatureType;
				this.privateKey = privateKey;
				this.digestCalculator = digestCalculator;
				this.signer = signer;
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
				return privateKey.getKeyID();
			}

			public OutputStream getOutputStream()
			{
				return new TeeOutputStream(new SignerOutputStream(signer), digestCalculator.getOutputStream());
			}

			public byte[] getSignature()
			{
				try
				{
					return signer.generateSignature();
				}
				catch (CryptoException)
				{ // TODO: need a specific runtime exception for PGP operators.
					throw new IllegalStateException("unable to create signature");
				}
			}

			public byte[] getDigest()
			{
				return digestCalculator.getDigest();
			}
		}
	}

}