using org.bouncycastle.asn1;

namespace org.bouncycastle.cms
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using SignerIdentifier = org.bouncycastle.asn1.cms.SignerIdentifier;
	using SignerInfo = org.bouncycastle.asn1.cms.SignerInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;
	using DefaultDigestAlgorithmIdentifierFinder = org.bouncycastle.@operator.DefaultDigestAlgorithmIdentifierFinder;
	using DigestAlgorithmIdentifierFinder = org.bouncycastle.@operator.DigestAlgorithmIdentifierFinder;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using Arrays = org.bouncycastle.util.Arrays;
	using TeeOutputStream = org.bouncycastle.util.io.TeeOutputStream;

	public class SignerInfoGenerator
	{
		private readonly SignerIdentifier signerIdentifier;
		private readonly CMSAttributeTableGenerator sAttrGen;
		private readonly CMSAttributeTableGenerator unsAttrGen;
		private readonly ContentSigner signer;
		private readonly DigestCalculator digester;
		private readonly DigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
		private readonly CMSSignatureEncryptionAlgorithmFinder sigEncAlgFinder;

		private byte[] calculatedDigest = null;
		private X509CertificateHolder certHolder;

		public SignerInfoGenerator(SignerIdentifier signerIdentifier, ContentSigner signer, DigestCalculatorProvider digesterProvider, CMSSignatureEncryptionAlgorithmFinder sigEncAlgFinder) : this(signerIdentifier, signer, digesterProvider, sigEncAlgFinder, false)
		{
		}

		public SignerInfoGenerator(SignerIdentifier signerIdentifier, ContentSigner signer, DigestCalculatorProvider digesterProvider, CMSSignatureEncryptionAlgorithmFinder sigEncAlgFinder, bool isDirectSignature)
		{
			this.signerIdentifier = signerIdentifier;
			this.signer = signer;

			if (digesterProvider != null)
			{
				this.digester = digesterProvider.get(digAlgFinder.find(signer.getAlgorithmIdentifier()));
			}
			else
			{
				this.digester = null;
			}

			if (isDirectSignature)
			{
				this.sAttrGen = null;
				this.unsAttrGen = null;
			}
			else
			{
				this.sAttrGen = new DefaultSignedAttributeTableGenerator();
				this.unsAttrGen = null;
			}

			this.sigEncAlgFinder = sigEncAlgFinder;
		}

		public SignerInfoGenerator(SignerInfoGenerator original, CMSAttributeTableGenerator sAttrGen, CMSAttributeTableGenerator unsAttrGen)
		{
			this.signerIdentifier = original.signerIdentifier;
			this.signer = original.signer;
			this.digester = original.digester;
			this.sigEncAlgFinder = original.sigEncAlgFinder;
			this.sAttrGen = sAttrGen;
			this.unsAttrGen = unsAttrGen;
		}

		public SignerInfoGenerator(SignerIdentifier signerIdentifier, ContentSigner signer, DigestCalculatorProvider digesterProvider, CMSSignatureEncryptionAlgorithmFinder sigEncAlgFinder, CMSAttributeTableGenerator sAttrGen, CMSAttributeTableGenerator unsAttrGen)
		{
			this.signerIdentifier = signerIdentifier;
			this.signer = signer;

			if (digesterProvider != null)
			{
				this.digester = digesterProvider.get(digAlgFinder.find(signer.getAlgorithmIdentifier()));
			}
			else
			{
				this.digester = null;
			}

			this.sAttrGen = sAttrGen;
			this.unsAttrGen = unsAttrGen;
			this.sigEncAlgFinder = sigEncAlgFinder;
		}

		public virtual SignerIdentifier getSID()
		{
			return signerIdentifier;
		}

		public virtual int getGeneratedVersion()
		{
			return signerIdentifier.isTagged() ? 3 : 1;
		}

		public virtual bool hasAssociatedCertificate()
		{
			return certHolder != null;
		}

		public virtual X509CertificateHolder getAssociatedCertificate()
		{
			return certHolder;
		}

		public virtual AlgorithmIdentifier getDigestAlgorithm()
		{
			if (digester != null)
			{
				return digester.getAlgorithmIdentifier();
			}

			return digAlgFinder.find(signer.getAlgorithmIdentifier());
		}

		public virtual OutputStream getCalculatingOutputStream()
		{
			if (digester != null)
			{
				if (sAttrGen == null)
				{
					return new TeeOutputStream(digester.getOutputStream(), signer.getOutputStream());
				}
				return digester.getOutputStream();
			}
			else
			{
				return signer.getOutputStream();
			}
		}

		public virtual SignerInfo generate(ASN1ObjectIdentifier contentType)
		{
			try
			{
				/* RFC 3852 5.4
				 * The result of the message digest calculation process depends on
				 * whether the signedAttrs field is present.  When the field is absent,
				 * the result is just the message digest of the content as described
				 *
				 * above.  When the field is present, however, the result is the message
				 * digest of the complete DER encoding of the SignedAttrs value
				 * contained in the signedAttrs field.
				 */
				ASN1Set signedAttr = null;

				AlgorithmIdentifier digestEncryptionAlgorithm = sigEncAlgFinder.findEncryptionAlgorithm(signer.getAlgorithmIdentifier());

				AlgorithmIdentifier digestAlg = null;

				if (sAttrGen != null)
				{
					digestAlg = digester.getAlgorithmIdentifier();
					calculatedDigest = digester.getDigest();
					Map parameters = getBaseParameters(contentType, digester.getAlgorithmIdentifier(), digestEncryptionAlgorithm, calculatedDigest);
					AttributeTable signed = sAttrGen.getAttributes(Collections.unmodifiableMap(parameters));

					signedAttr = getAttributeSet(signed);

					// sig must be composed from the DER encoding.
					OutputStream sOut = signer.getOutputStream();

					sOut.write(signedAttr.getEncoded(ASN1Encoding_Fields.DER));

					sOut.close();
				}
				else
				{
					if (digester != null)
					{
						digestAlg = digester.getAlgorithmIdentifier();
						calculatedDigest = digester.getDigest();
					}
					else
					{
						digestAlg = digAlgFinder.find(signer.getAlgorithmIdentifier());
						calculatedDigest = null;
					}
				}

				byte[] sigBytes = signer.getSignature();

				ASN1Set unsignedAttr = null;
				if (unsAttrGen != null)
				{
					Map parameters = getBaseParameters(contentType, digestAlg, digestEncryptionAlgorithm, calculatedDigest);
					parameters.put(CMSAttributeTableGenerator_Fields.SIGNATURE, Arrays.clone(sigBytes));

					AttributeTable unsigned = unsAttrGen.getAttributes(Collections.unmodifiableMap(parameters));

					unsignedAttr = getAttributeSet(unsigned);
				}

				return new SignerInfo(signerIdentifier, digestAlg, signedAttr, digestEncryptionAlgorithm, new DEROctetString(sigBytes), unsignedAttr);
			}
			catch (IOException e)
			{
				throw new CMSException("encoding error.", e);
			}
		}

		public virtual void setAssociatedCertificate(X509CertificateHolder certHolder)
		{
			this.certHolder = certHolder;
		}

		private ASN1Set getAttributeSet(AttributeTable attr)
		{
			if (attr != null)
			{
				return new DERSet(attr.toASN1EncodableVector());
			}

			return null;
		}

		private Map getBaseParameters(ASN1ObjectIdentifier contentType, AlgorithmIdentifier digAlgId, AlgorithmIdentifier sigAlgId, byte[] hash)
		{
			Map param = new HashMap();

			if (contentType != null)
			{
				param.put(CMSAttributeTableGenerator_Fields.CONTENT_TYPE, contentType);
			}

			param.put(CMSAttributeTableGenerator_Fields.DIGEST_ALGORITHM_IDENTIFIER, digAlgId);
			param.put(CMSAttributeTableGenerator_Fields.SIGNATURE_ALGORITHM_IDENTIFIER, sigAlgId);
			param.put(CMSAttributeTableGenerator_Fields.DIGEST, Arrays.clone(hash));

			return param;
		}

		public virtual byte[] getCalculatedDigest()
		{
			if (calculatedDigest != null)
			{
				return Arrays.clone(calculatedDigest);
			}

			return null;
		}

		public virtual CMSAttributeTableGenerator getSignedAttributeTableGenerator()
		{
			return sAttrGen;
		}

		public virtual CMSAttributeTableGenerator getUnsignedAttributeTableGenerator()
		{
			return unsAttrGen;
		}
	}

}