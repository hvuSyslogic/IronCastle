namespace org.bouncycastle.cms
{
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using SignerIdentifier = org.bouncycastle.asn1.cms.SignerIdentifier;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;

	/// <summary>
	/// Builder for SignerInfo generator objects.
	/// </summary>
	public class SignerInfoGeneratorBuilder
	{
		private DigestCalculatorProvider digestProvider;
		private bool directSignature;
		private CMSAttributeTableGenerator signedGen;
		private CMSAttributeTableGenerator unsignedGen;
		private CMSSignatureEncryptionAlgorithmFinder sigEncAlgFinder;

		/// <summary>
		///  Base constructor.
		/// </summary>
		/// <param name="digestProvider">  a provider of digest calculators for the algorithms required in the signature and attribute calculations. </param>
		public SignerInfoGeneratorBuilder(DigestCalculatorProvider digestProvider) : this(digestProvider, new DefaultCMSSignatureEncryptionAlgorithmFinder())
		{
		}

		/// <summary>
		/// Base constructor with a particular finder for signature algorithms.
		/// </summary>
		/// <param name="digestProvider"> a provider of digest calculators for the algorithms required in the signature and attribute calculations. </param>
		/// <param name="sigEncAlgFinder"> finder for algorithm IDs to store for the signature encryption/signature algorithm field. </param>
		public SignerInfoGeneratorBuilder(DigestCalculatorProvider digestProvider, CMSSignatureEncryptionAlgorithmFinder sigEncAlgFinder)
		{
			this.digestProvider = digestProvider;
			this.sigEncAlgFinder = sigEncAlgFinder;
		}

		/// <summary>
		/// If the passed in flag is true, the signer signature will be based on the data, not
		/// a collection of signed attributes, and no signed attributes will be included.
		/// </summary>
		/// <returns> the builder object </returns>
		public virtual SignerInfoGeneratorBuilder setDirectSignature(bool hasNoSignedAttributes)
		{
			this.directSignature = hasNoSignedAttributes;

			return this;
		}

		/// <summary>
		///  Provide a custom signed attribute generator.
		/// </summary>
		/// <param name="signedGen"> a generator of signed attributes. </param>
		/// <returns> the builder object </returns>
		public virtual SignerInfoGeneratorBuilder setSignedAttributeGenerator(CMSAttributeTableGenerator signedGen)
		{
			this.signedGen = signedGen;

			return this;
		}

		/// <summary>
		/// Provide a generator of unsigned attributes.
		/// </summary>
		/// <param name="unsignedGen">  a generator for signed attributes. </param>
		/// <returns> the builder object </returns>
		public virtual SignerInfoGeneratorBuilder setUnsignedAttributeGenerator(CMSAttributeTableGenerator unsignedGen)
		{
			this.unsignedGen = unsignedGen;

			return this;
		}

		/// <summary>
		/// Build a generator with the passed in certHolder issuer and serial number as the signerIdentifier.
		/// </summary>
		/// <param name="contentSigner">  operator for generating the final signature in the SignerInfo with. </param>
		/// <param name="certHolder">  carrier for the X.509 certificate related to the contentSigner. </param>
		/// <returns>  a SignerInfoGenerator </returns>
		/// <exception cref="OperatorCreationException">   if the generator cannot be built. </exception>
		public virtual SignerInfoGenerator build(ContentSigner contentSigner, X509CertificateHolder certHolder)
		{
			SignerIdentifier sigId = new SignerIdentifier(new IssuerAndSerialNumber(certHolder.toASN1Structure()));

			SignerInfoGenerator sigInfoGen = createGenerator(contentSigner, sigId);

			sigInfoGen.setAssociatedCertificate(certHolder);

			return sigInfoGen;
		}

		/// <summary>
		/// Build a generator with the passed in subjectKeyIdentifier as the signerIdentifier. If used  you should
		/// try to follow the calculation described in RFC 5280 section 4.2.1.2.
		/// </summary>
		/// <param name="contentSigner">  operator for generating the final signature in the SignerInfo with. </param>
		/// <param name="subjectKeyIdentifier">    key identifier to identify the public key for verifying the signature. </param>
		/// <returns>  a SignerInfoGenerator </returns>
		/// <exception cref="OperatorCreationException"> if the generator cannot be built. </exception>
		public virtual SignerInfoGenerator build(ContentSigner contentSigner, byte[] subjectKeyIdentifier)
		{
			SignerIdentifier sigId = new SignerIdentifier(new DEROctetString(subjectKeyIdentifier));

			return createGenerator(contentSigner, sigId);
		}

		private SignerInfoGenerator createGenerator(ContentSigner contentSigner, SignerIdentifier sigId)
		{
			if (directSignature)
			{
				return new SignerInfoGenerator(sigId, contentSigner, digestProvider, sigEncAlgFinder, true);
			}

			if (signedGen != null || unsignedGen != null)
			{
				if (signedGen == null)
				{
					signedGen = new DefaultSignedAttributeTableGenerator();
				}

				return new SignerInfoGenerator(sigId, contentSigner, digestProvider, sigEncAlgFinder, signedGen, unsignedGen);
			}

			return new SignerInfoGenerator(sigId, contentSigner, digestProvider, sigEncAlgFinder);
		}
	}

}