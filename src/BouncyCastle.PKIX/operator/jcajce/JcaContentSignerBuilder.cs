using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.@operator.jcajce
{

	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RSASSAPSSparams = org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using OutputStreamFactory = org.bouncycastle.jcajce.io.OutputStreamFactory;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JcaContentSignerBuilder
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private SecureRandom random;
		private string signatureAlgorithm;
		private AlgorithmIdentifier sigAlgId;
		private AlgorithmParameterSpec sigAlgSpec;

		public JcaContentSignerBuilder(string signatureAlgorithm)
		{
			this.signatureAlgorithm = signatureAlgorithm;
			this.sigAlgId = (new DefaultSignatureAlgorithmIdentifierFinder()).find(signatureAlgorithm);
			this.sigAlgSpec = null;
		}

		public JcaContentSignerBuilder(string signatureAlgorithm, AlgorithmParameterSpec sigParamSpec)
		{
			this.signatureAlgorithm = signatureAlgorithm;

			if (sigParamSpec is PSSParameterSpec)
			{
				PSSParameterSpec pssSpec = (PSSParameterSpec)sigParamSpec;

				this.sigAlgSpec = pssSpec;
				this.sigAlgId = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_RSASSA_PSS, createPSSParams(pssSpec));
			}
			else
			{
				throw new IllegalArgumentException("unknown sigParamSpec: " + ((sigParamSpec == null) ? "null" : sigParamSpec.GetType().getName()));
			}
		}

		public virtual JcaContentSignerBuilder setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		public virtual JcaContentSignerBuilder setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		public virtual JcaContentSignerBuilder setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public virtual ContentSigner build(PrivateKey privateKey)
		{
			try
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.security.Signature sig = helper.createSignature(sigAlgId);
				Signature sig = helper.createSignature(sigAlgId);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.x509.AlgorithmIdentifier signatureAlgId = sigAlgId;
				AlgorithmIdentifier signatureAlgId = sigAlgId;

				if (random != null)
				{
					sig.initSign(privateKey, random);
				}
				else
				{
					sig.initSign(privateKey);
				}

				return new ContentSignerAnonymousInnerClass(this, sig, signatureAlgId);
			}
			catch (GeneralSecurityException e)
			{
				throw new OperatorCreationException("cannot create signer: " + e.Message, e);
			}
		}

		public class ContentSignerAnonymousInnerClass : ContentSigner
		{
			private readonly JcaContentSignerBuilder outerInstance;

			private Signature sig;
			private AlgorithmIdentifier signatureAlgId;

			public ContentSignerAnonymousInnerClass(JcaContentSignerBuilder outerInstance, Signature sig, AlgorithmIdentifier signatureAlgId)
			{
				this.outerInstance = outerInstance;
				this.sig = sig;
				this.signatureAlgId = signatureAlgId;
				stream = OutputStreamFactory.createStream(sig);
			}

			private OutputStream stream;

			public AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return signatureAlgId;
			}

			public OutputStream getOutputStream()
			{
				return stream;
			}

			public byte[] getSignature()
			{
				try
				{
					return sig.sign();
				}
				catch (SignatureException e)
				{
					throw new RuntimeOperatorException("exception obtaining signature: " + e.Message, e);
				}
			}
		}

		private static RSASSAPSSparams createPSSParams(PSSParameterSpec pssSpec)
		{
			DigestAlgorithmIdentifierFinder digFinder = new DefaultDigestAlgorithmIdentifierFinder();
			   AlgorithmIdentifier digId = digFinder.find(pssSpec.getDigestAlgorithm());
			   AlgorithmIdentifier mgfDig = digFinder.find(((MGF1ParameterSpec)pssSpec.getMGFParameters()).getDigestAlgorithm());

			return new RSASSAPSSparams(digId, new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_mgf1, mgfDig), new ASN1Integer(pssSpec.getSaltLength()), new ASN1Integer(pssSpec.getTrailerField()));
		}
	}

}