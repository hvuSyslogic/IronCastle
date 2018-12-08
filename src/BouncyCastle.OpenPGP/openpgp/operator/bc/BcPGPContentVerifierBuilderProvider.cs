namespace org.bouncycastle.openpgp.@operator.bc
{

	using Signer = org.bouncycastle.crypto.Signer;

	public class BcPGPContentVerifierBuilderProvider : PGPContentVerifierBuilderProvider
	{
		private BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();

		public BcPGPContentVerifierBuilderProvider()
		{
		}

		public virtual PGPContentVerifierBuilder get(int keyAlgorithm, int hashAlgorithm)
		{
			return new BcPGPContentVerifierBuilder(this, keyAlgorithm, hashAlgorithm);
		}

		public class BcPGPContentVerifierBuilder : PGPContentVerifierBuilder
		{
			private readonly BcPGPContentVerifierBuilderProvider outerInstance;

			internal int hashAlgorithm;
			internal int keyAlgorithm;

			public BcPGPContentVerifierBuilder(BcPGPContentVerifierBuilderProvider outerInstance, int keyAlgorithm, int hashAlgorithm)
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
//ORIGINAL LINE: final org.bouncycastle.crypto.Signer signer = BcImplProvider.createSigner(keyAlgorithm, hashAlgorithm);
				Signer signer = BcImplProvider.createSigner(keyAlgorithm, hashAlgorithm);

				signer.init(false, outerInstance.keyConverter.getPublicKey(publicKey));

				return new PGPContentVerifierAnonymousInnerClass(this, publicKey, signer);
			}

			public class PGPContentVerifierAnonymousInnerClass : PGPContentVerifier
			{
				private readonly BcPGPContentVerifierBuilder outerInstance;

				private PGPPublicKey publicKey;
				private Signer signer;

				public PGPContentVerifierAnonymousInnerClass(BcPGPContentVerifierBuilder outerInstance, PGPPublicKey publicKey, Signer signer)
				{
					this.outerInstance = outerInstance;
					this.publicKey = publicKey;
					this.signer = signer;
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
					return signer.verifySignature(expected);
				}

				public OutputStream getOutputStream()
				{
					return new SignerOutputStream(signer);
				}
			}
		}
	}

}