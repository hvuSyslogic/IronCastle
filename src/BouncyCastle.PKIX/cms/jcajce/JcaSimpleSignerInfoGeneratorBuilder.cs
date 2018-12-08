namespace org.bouncycastle.cms.jcajce
{

	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JcaX509CertificateHolder = org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using JcaContentSignerBuilder = org.bouncycastle.@operator.jcajce.JcaContentSignerBuilder;
	using JcaDigestCalculatorProviderBuilder = org.bouncycastle.@operator.jcajce.JcaDigestCalculatorProviderBuilder;

	/// <summary>
	/// Use this class if you are using a provider that has all the facilities you
	/// need.
	/// <para>
	/// For example:
	/// <pre>
	///      CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
	///      ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(signKP.getPrivate());
	/// 
	///      gen.addSignerInfoGenerator(
	///                new JcaSignerInfoGeneratorBuilder(
	///                     new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
	///                     .build(sha1Signer, signCert));
	/// </pre>
	/// becomes:
	/// <pre>
	///      CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
	/// 
	///      gen.addSignerInfoGenerator(
	///                new JcaSimpleSignerInfoGeneratorBuilder()
	///                     .setProvider("BC")
	///                     .build("SHA1withRSA", signKP.getPrivate(), signCert));
	/// </pre>
	/// </para>
	/// </summary>
	public class JcaSimpleSignerInfoGeneratorBuilder
	{
		private Helper helper;

		private bool hasNoSignedAttributes;
		private CMSAttributeTableGenerator signedGen;
		private CMSAttributeTableGenerator unsignedGen;

		public JcaSimpleSignerInfoGeneratorBuilder()
		{
			this.helper = new Helper(this);
		}

		public virtual JcaSimpleSignerInfoGeneratorBuilder setProvider(string providerName)
		{
			this.helper = new NamedHelper(this, providerName);

			return this;
		}

		public virtual JcaSimpleSignerInfoGeneratorBuilder setProvider(Provider provider)
		{
			this.helper = new ProviderHelper(this, provider);

			return this;
		}

		/// <summary>
		/// If the passed in flag is true, the signer signature will be based on the data, not
		/// a collection of signed attributes, and no signed attributes will be included.
		/// </summary>
		/// <returns> the builder object </returns>
		public virtual JcaSimpleSignerInfoGeneratorBuilder setDirectSignature(bool hasNoSignedAttributes)
		{
			this.hasNoSignedAttributes = hasNoSignedAttributes;

			return this;
		}

		public virtual JcaSimpleSignerInfoGeneratorBuilder setSignedAttributeGenerator(CMSAttributeTableGenerator signedGen)
		{
			this.signedGen = signedGen;

			return this;
		}

		/// <summary>
		/// set up a DefaultSignedAttributeTableGenerator primed with the passed in AttributeTable.
		/// </summary>
		/// <param name="attrTable"> table of attributes for priming generator </param>
		/// <returns> this. </returns>
		public virtual JcaSimpleSignerInfoGeneratorBuilder setSignedAttributeGenerator(AttributeTable attrTable)
		{
			this.signedGen = new DefaultSignedAttributeTableGenerator(attrTable);

			return this;
		}

		public virtual JcaSimpleSignerInfoGeneratorBuilder setUnsignedAttributeGenerator(CMSAttributeTableGenerator unsignedGen)
		{
			this.unsignedGen = unsignedGen;

			return this;
		}

		public virtual SignerInfoGenerator build(string algorithmName, PrivateKey privateKey, X509CertificateHolder certificate)
		{
			ContentSigner contentSigner = helper.createContentSigner(algorithmName, privateKey);

			return configureAndBuild().build(contentSigner, certificate);
		}

		public virtual SignerInfoGenerator build(string algorithmName, PrivateKey privateKey, X509Certificate certificate)
		{
			ContentSigner contentSigner = helper.createContentSigner(algorithmName, privateKey);

			return configureAndBuild().build(contentSigner, new JcaX509CertificateHolder(certificate));
		}

		public virtual SignerInfoGenerator build(string algorithmName, PrivateKey privateKey, byte[] keyIdentifier)
		{
			ContentSigner contentSigner = helper.createContentSigner(algorithmName, privateKey);

			return configureAndBuild().build(contentSigner, keyIdentifier);
		}

		private SignerInfoGeneratorBuilder configureAndBuild()
		{
			SignerInfoGeneratorBuilder infoGeneratorBuilder = new SignerInfoGeneratorBuilder(helper.createDigestCalculatorProvider());

			infoGeneratorBuilder.setDirectSignature(hasNoSignedAttributes);
			infoGeneratorBuilder.setSignedAttributeGenerator(signedGen);
			infoGeneratorBuilder.setUnsignedAttributeGenerator(unsignedGen);

			return infoGeneratorBuilder;
		}

		public class Helper
		{
			private readonly JcaSimpleSignerInfoGeneratorBuilder outerInstance;

			public Helper(JcaSimpleSignerInfoGeneratorBuilder outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public virtual ContentSigner createContentSigner(string algorithm, PrivateKey privateKey)
			{
				return (new JcaContentSignerBuilder(algorithm)).build(privateKey);
			}

			public virtual DigestCalculatorProvider createDigestCalculatorProvider()
			{
				return (new JcaDigestCalculatorProviderBuilder()).build();
			}
		}

		public class NamedHelper : Helper
		{
			private readonly JcaSimpleSignerInfoGeneratorBuilder outerInstance;

			internal readonly string providerName;

			public NamedHelper(JcaSimpleSignerInfoGeneratorBuilder outerInstance, string providerName) : base(outerInstance)
			{
				this.outerInstance = outerInstance;
				this.providerName = providerName;
			}

			public override ContentSigner createContentSigner(string algorithm, PrivateKey privateKey)
			{
				return (new JcaContentSignerBuilder(algorithm)).setProvider(providerName).build(privateKey);
			}

			public override DigestCalculatorProvider createDigestCalculatorProvider()
			{
				return (new JcaDigestCalculatorProviderBuilder()).setProvider(providerName).build();
			}
		}

		public class ProviderHelper : Helper
		{
			private readonly JcaSimpleSignerInfoGeneratorBuilder outerInstance;

			internal readonly Provider provider;

			public ProviderHelper(JcaSimpleSignerInfoGeneratorBuilder outerInstance, Provider provider) : base(outerInstance)
			{
				this.outerInstance = outerInstance;
				this.provider = provider;
			}

			public override ContentSigner createContentSigner(string algorithm, PrivateKey privateKey)
			{
				return (new JcaContentSignerBuilder(algorithm)).setProvider(provider).build(privateKey);
			}

			public override DigestCalculatorProvider createDigestCalculatorProvider()
			{
				return (new JcaDigestCalculatorProviderBuilder()).setProvider(provider).build();
			}
		}
	}

}