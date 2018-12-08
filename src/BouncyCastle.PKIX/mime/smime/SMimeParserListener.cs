namespace org.bouncycastle.mime.smime
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CMSEnvelopedDataParser = org.bouncycastle.cms.CMSEnvelopedDataParser;
	using CMSException = org.bouncycastle.cms.CMSException;
	using CMSSignedData = org.bouncycastle.cms.CMSSignedData;
	using OriginatorInformation = org.bouncycastle.cms.OriginatorInformation;
	using RecipientInformationStore = org.bouncycastle.cms.RecipientInformationStore;
	using SignerInformationStore = org.bouncycastle.cms.SignerInformationStore;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using Store = org.bouncycastle.util.Store;
	using Streams = org.bouncycastle.util.io.Streams;

	public abstract class SMimeParserListener : MimeParserListener
	{
		private DigestCalculator[] digestCalculators;
		private SMimeMultipartContext parent;

		public virtual MimeContext createContext(MimeParserContext parserContext, Headers headers)
		{
			if (headers.isMultipart())
			{
				parent = new SMimeMultipartContext(parserContext, headers);
				this.digestCalculators = parent.getDigestCalculators();
				return parent;
			}
			else
			{
				return new ConstantMimeContext();
			}
		}

		public virtual void @object(MimeParserContext parserContext, Headers headers, InputStream inputStream)
		{
			try
			{
				if (headers.getContentType().Equals("application/pkcs7-signature") || headers.getContentType().Equals("application/x-pkcs7-signature"))
				{
					Map<ASN1ObjectIdentifier, byte[]> hashes = new HashMap<ASN1ObjectIdentifier, byte[]>();

					for (int i = 0; i != digestCalculators.Length; i++)
					{
						digestCalculators[i].getOutputStream().close();

						hashes.put(digestCalculators[i].getAlgorithmIdentifier().getAlgorithm(), digestCalculators[i].getDigest());
					}

					byte[] sigBlock = Streams.readAll(inputStream);

					CMSSignedData signedData = new CMSSignedData(hashes, sigBlock);

					signedData(parserContext, headers, signedData.getCertificates(), signedData.getCRLs(), signedData.getAttributeCertificates(), signedData.getSignerInfos());
				}
				else if (headers.getContentType().Equals("application/pkcs7-mime") || headers.getContentType().Equals("application/x-pkcs7-mime"))
				{
					CMSEnvelopedDataParser envelopedDataParser = new CMSEnvelopedDataParser(inputStream);

					envelopedData(parserContext, headers, envelopedDataParser.getOriginatorInfo(), envelopedDataParser.getRecipientInfos());

					envelopedDataParser.close();
				}
				else
				{
					content(parserContext, headers, inputStream);
				}
			}
			catch (CMSException e)
			{
				throw new MimeIOException("CMS failure: " + e.Message, e);
			}
		}

		public virtual void content(MimeParserContext parserContext, Headers headers, InputStream inputStream)
		{
			throw new IllegalStateException("content handling not implemented");
		}

		public virtual void signedData(MimeParserContext parserContext, Headers headers, Store certificates, Store CRLs, Store attributeCertificates, SignerInformationStore signers)
		{
			throw new IllegalStateException("signedData handling not implemented");
		}

		public virtual void envelopedData(MimeParserContext parserContext, Headers headers, OriginatorInformation originatorInformation, RecipientInformationStore recipients)
		{
			throw new IllegalStateException("envelopedData handling not implemented");
		}
	}

}