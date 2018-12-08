namespace org.bouncycastle.cms.jcajce
{

	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using ContentVerifierProvider = org.bouncycastle.@operator.ContentVerifierProvider;
	using DefaultSignatureAlgorithmIdentifierFinder = org.bouncycastle.@operator.DefaultSignatureAlgorithmIdentifierFinder;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using JcaContentVerifierProviderBuilder = org.bouncycastle.@operator.jcajce.JcaContentVerifierProviderBuilder;
	using JcaDigestCalculatorProviderBuilder = org.bouncycastle.@operator.jcajce.JcaDigestCalculatorProviderBuilder;

	public class JcaSimpleSignerInfoVerifierBuilder
	{
		private bool InstanceFieldsInitialized = false;

		public JcaSimpleSignerInfoVerifierBuilder()
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
		}

		private void InitializeInstanceFields()
		{
			helper = new Helper(this);
		}

		private Helper helper;

		public virtual JcaSimpleSignerInfoVerifierBuilder setProvider(Provider provider)
		{
			this.helper = new ProviderHelper(this, provider);

			return this;
		}

		public virtual JcaSimpleSignerInfoVerifierBuilder setProvider(string providerName)
		{
			this.helper = new NamedHelper(this, providerName);

			return this;
		}

		public virtual SignerInformationVerifier build(X509CertificateHolder certHolder)
		{
			return new SignerInformationVerifier(new DefaultCMSSignatureAlgorithmNameGenerator(), new DefaultSignatureAlgorithmIdentifierFinder(), helper.createContentVerifierProvider(certHolder), helper.createDigestCalculatorProvider());
		}

		public virtual SignerInformationVerifier build(X509Certificate certificate)
		{
			return new SignerInformationVerifier(new DefaultCMSSignatureAlgorithmNameGenerator(), new DefaultSignatureAlgorithmIdentifierFinder(), helper.createContentVerifierProvider(certificate), helper.createDigestCalculatorProvider());
		}

		public virtual SignerInformationVerifier build(PublicKey pubKey)
		{
			return new SignerInformationVerifier(new DefaultCMSSignatureAlgorithmNameGenerator(), new DefaultSignatureAlgorithmIdentifierFinder(), helper.createContentVerifierProvider(pubKey), helper.createDigestCalculatorProvider());
		}

		public class Helper
		{
			private readonly JcaSimpleSignerInfoVerifierBuilder outerInstance;

			public Helper(JcaSimpleSignerInfoVerifierBuilder outerInstance)
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
			private readonly JcaSimpleSignerInfoVerifierBuilder outerInstance;

			internal readonly string providerName;

			public NamedHelper(JcaSimpleSignerInfoVerifierBuilder outerInstance, string providerName) : base(outerInstance)
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
			private readonly JcaSimpleSignerInfoVerifierBuilder outerInstance;

			internal readonly Provider provider;

			public ProviderHelper(JcaSimpleSignerInfoVerifierBuilder outerInstance, Provider provider) : base(outerInstance)
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