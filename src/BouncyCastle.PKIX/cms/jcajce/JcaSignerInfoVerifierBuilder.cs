namespace org.bouncycastle.cms.jcajce
{

	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using ContentVerifierProvider = org.bouncycastle.@operator.ContentVerifierProvider;
	using DefaultSignatureAlgorithmIdentifierFinder = org.bouncycastle.@operator.DefaultSignatureAlgorithmIdentifierFinder;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using SignatureAlgorithmIdentifierFinder = org.bouncycastle.@operator.SignatureAlgorithmIdentifierFinder;
	using JcaContentVerifierProviderBuilder = org.bouncycastle.@operator.jcajce.JcaContentVerifierProviderBuilder;
	using JcaDigestCalculatorProviderBuilder = org.bouncycastle.@operator.jcajce.JcaDigestCalculatorProviderBuilder;

	public class JcaSignerInfoVerifierBuilder
	{
		private bool InstanceFieldsInitialized = false;

		private void InitializeInstanceFields()
		{
			helper = new Helper(this);
		}

		private Helper helper;
		private DigestCalculatorProvider digestProvider;
		private CMSSignatureAlgorithmNameGenerator sigAlgNameGen = new DefaultCMSSignatureAlgorithmNameGenerator();
		private SignatureAlgorithmIdentifierFinder sigAlgIDFinder = new DefaultSignatureAlgorithmIdentifierFinder();

		public JcaSignerInfoVerifierBuilder(DigestCalculatorProvider digestProvider)
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
			this.digestProvider = digestProvider;
		}

		public virtual JcaSignerInfoVerifierBuilder setProvider(Provider provider)
		{
			this.helper = new ProviderHelper(this, provider);

			return this;
		}

		public virtual JcaSignerInfoVerifierBuilder setProvider(string providerName)
		{
			this.helper = new NamedHelper(this, providerName);

			return this;
		}

		/// <summary>
		/// Override the default signature algorithm name generator.
		/// </summary>
		/// <param name="sigAlgNameGen"> the algorithm name generator to use. </param>
		/// <returns> the current builder. </returns>
		public virtual JcaSignerInfoVerifierBuilder setSignatureAlgorithmNameGenerator(CMSSignatureAlgorithmNameGenerator sigAlgNameGen)
		{
			this.sigAlgNameGen = sigAlgNameGen;

			return this;
		}

		public virtual JcaSignerInfoVerifierBuilder setSignatureAlgorithmFinder(SignatureAlgorithmIdentifierFinder sigAlgIDFinder)
		{
			this.sigAlgIDFinder = sigAlgIDFinder;

			return this;
		}

		public virtual SignerInformationVerifier build(X509CertificateHolder certHolder)
		{
			return new SignerInformationVerifier(sigAlgNameGen, sigAlgIDFinder, helper.createContentVerifierProvider(certHolder), digestProvider);
		}

		public virtual SignerInformationVerifier build(X509Certificate certificate)
		{
			return new SignerInformationVerifier(sigAlgNameGen, sigAlgIDFinder, helper.createContentVerifierProvider(certificate), digestProvider);
		}

		public virtual SignerInformationVerifier build(PublicKey pubKey)
		{
			return new SignerInformationVerifier(sigAlgNameGen, sigAlgIDFinder, helper.createContentVerifierProvider(pubKey), digestProvider);
		}

		public class Helper
		{
			private readonly JcaSignerInfoVerifierBuilder outerInstance;

			public Helper(JcaSignerInfoVerifierBuilder outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public virtual ContentVerifierProvider createContentVerifierProvider(PublicKey publicKey)
			{
				return (new JcaContentVerifierProviderBuilder()).build(publicKey);
			}

			public virtual ContentVerifierProvider createContentVerifierProvider(X509Certificate certificate)
			{
				return (new JcaContentVerifierProviderBuilder()).build(certificate);
			}

			public virtual ContentVerifierProvider createContentVerifierProvider(X509CertificateHolder certHolder)
			{
				return (new JcaContentVerifierProviderBuilder()).build(certHolder);
			}

			public virtual DigestCalculatorProvider createDigestCalculatorProvider()
			{
				return (new JcaDigestCalculatorProviderBuilder()).build();
			}
		}

		public class NamedHelper : Helper
		{
			private readonly JcaSignerInfoVerifierBuilder outerInstance;

			internal readonly string providerName;

			public NamedHelper(JcaSignerInfoVerifierBuilder outerInstance, string providerName) : base(outerInstance)
			{
				this.outerInstance = outerInstance;
				this.providerName = providerName;
			}

			public override ContentVerifierProvider createContentVerifierProvider(PublicKey publicKey)
			{
				return (new JcaContentVerifierProviderBuilder()).setProvider(providerName).build(publicKey);
			}

			public override ContentVerifierProvider createContentVerifierProvider(X509Certificate certificate)
			{
				return (new JcaContentVerifierProviderBuilder()).setProvider(providerName).build(certificate);
			}

			public override DigestCalculatorProvider createDigestCalculatorProvider()
			{
				return (new JcaDigestCalculatorProviderBuilder()).setProvider(providerName).build();
			}

			public override ContentVerifierProvider createContentVerifierProvider(X509CertificateHolder certHolder)
			{
				return (new JcaContentVerifierProviderBuilder()).setProvider(providerName).build(certHolder);
			}
		}

		public class ProviderHelper : Helper
		{
			private readonly JcaSignerInfoVerifierBuilder outerInstance;

			internal readonly Provider provider;

			public ProviderHelper(JcaSignerInfoVerifierBuilder outerInstance, Provider provider) : base(outerInstance)
			{
				this.outerInstance = outerInstance;
				this.provider = provider;
			}

			public override ContentVerifierProvider createContentVerifierProvider(PublicKey publicKey)
			{
				return (new JcaContentVerifierProviderBuilder()).setProvider(provider).build(publicKey);
			}

			public override ContentVerifierProvider createContentVerifierProvider(X509Certificate certificate)
			{
				return (new JcaContentVerifierProviderBuilder()).setProvider(provider).build(certificate);
			}

			public override DigestCalculatorProvider createDigestCalculatorProvider()
			{
				return (new JcaDigestCalculatorProviderBuilder()).setProvider(provider).build();
			}

			public override ContentVerifierProvider createContentVerifierProvider(X509CertificateHolder certHolder)
			{
				return (new JcaContentVerifierProviderBuilder()).setProvider(provider).build(certHolder);
			}
		}
	}

}