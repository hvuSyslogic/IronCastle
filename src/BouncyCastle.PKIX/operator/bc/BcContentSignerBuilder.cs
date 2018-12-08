namespace org.bouncycastle.@operator.bc
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CryptoException = org.bouncycastle.crypto.CryptoException;
	using Signer = org.bouncycastle.crypto.Signer;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;

	public abstract class BcContentSignerBuilder
	{
		private SecureRandom random;
		private AlgorithmIdentifier sigAlgId;
		private AlgorithmIdentifier digAlgId;

		protected internal BcDigestProvider digestProvider;

		public BcContentSignerBuilder(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
		{
			this.sigAlgId = sigAlgId;
			this.digAlgId = digAlgId;
			this.digestProvider = BcDefaultDigestProvider.INSTANCE;
		}

		public virtual BcContentSignerBuilder setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public virtual ContentSigner build(AsymmetricKeyParameter privateKey)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.Signer sig = createSigner(sigAlgId, digAlgId);
			Signer sig = createSigner(sigAlgId, digAlgId);

			if (random != null)
			{
				sig.init(true, new ParametersWithRandom(privateKey, random));
			}
			else
			{
				sig.init(true, privateKey);
			}

			return new ContentSignerAnonymousInnerClass(this, sig);
		}

		public class ContentSignerAnonymousInnerClass : ContentSigner
		{
			private readonly BcContentSignerBuilder outerInstance;

			private Signer sig;

			public ContentSignerAnonymousInnerClass(BcContentSignerBuilder outerInstance, Signer sig)
			{
				this.outerInstance = outerInstance;
				this.sig = sig;
				stream = new BcSignerOutputStream(sig);
			}

			private BcSignerOutputStream stream;

			public AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return outerInstance.sigAlgId;
			}

			public OutputStream getOutputStream()
			{
				return stream;
			}

			public byte[] getSignature()
			{
				try
				{
					return stream.getSignature();
				}
				catch (CryptoException e)
				{
					throw new RuntimeOperatorException("exception obtaining signature: " + e.Message, e);
				}
			}
		}

		public abstract Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier algorithmIdentifier);
	}

}