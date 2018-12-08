namespace org.bouncycastle.cms.jcajce
{

	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JcaX509CertificateHolder = org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;

	public class JcaSignerInfoGeneratorBuilder
	{
		private SignerInfoGeneratorBuilder builder;

		/// <summary>
		///  Base constructor.
		/// </summary>
		/// <param name="digestProvider">  a provider of digest calculators for the algorithms required in the signature and attribute calculations. </param>
		public JcaSignerInfoGeneratorBuilder(DigestCalculatorProvider digestProvider) : this(digestProvider, new DefaultCMSSignatureEncryptionAlgorithmFinder())
		{
		}

		/// <summary>
		/// Base constructor with a particular finder for signature algorithms.
		/// </summary>
		/// <param name="digestProvider"> a provider of digest calculators for the algorithms required in the signature and attribute calculations. </param>
		/// <param name="sigEncAlgFinder"> finder for algorithm IDs to store for the signature encryption/signature algorithm field. </param>
		public JcaSignerInfoGeneratorBuilder(DigestCalculatorProvider digestProvider, CMSSignatureEncryptionAlgorithmFinder sigEncAlgFinder)
		{
			builder = new SignerInfoGeneratorBuilder(digestProvider, sigEncAlgFinder);
		}

		/// <summary>
		/// If the passed in flag is true, the signer signature will be based on the data, not
		/// a collection of signed attributes, and no signed attributes will be included.
		/// </summary>
		/// <returns> the builder object </returns>
		public virtual JcaSignerInfoGeneratorBuilder setDirectSignature(bool hasNoSignedAttributes)
		{
			builder.setDirectSignature(hasNoSignedAttributes);

			return this;
		}

		public virtual JcaSignerInfoGeneratorBuilder setSignedAttributeGenerator(CMSAttributeTableGenerator signedGen)
		{
			builder.setSignedAttributeGenerator(signedGen);

			return this;
		}

		public virtual JcaSignerInfoGeneratorBuilder setUnsignedAttributeGenerator(CMSAttributeTableGenerator unsignedGen)
		{
			builder.setUnsignedAttributeGenerator(unsignedGen);

			return this;
		}

		public virtual SignerInfoGenerator build(ContentSigner contentSigner, X509CertificateHolder certHolder)
		{
			return builder.build(contentSigner, certHolder);
		}

		public virtual SignerInfoGenerator build(ContentSigner contentSigner, byte[] keyIdentifier)
		{
			return builder.build(contentSigner, keyIdentifier);
		}

		public virtual SignerInfoGenerator build(ContentSigner contentSigner, X509Certificate certificate)
		{
			return this.build(contentSigner, new JcaX509CertificateHolder(certificate));
		}
	}

}