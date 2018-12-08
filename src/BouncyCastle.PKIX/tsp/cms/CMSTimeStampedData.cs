using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.tsp.cms
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using DERIA5String = org.bouncycastle.asn1.DERIA5String;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using Evidence = org.bouncycastle.asn1.cms.Evidence;
	using TimeStampAndCRL = org.bouncycastle.asn1.cms.TimeStampAndCRL;
	using TimeStampTokenEvidence = org.bouncycastle.asn1.cms.TimeStampTokenEvidence;
	using TimeStampedData = org.bouncycastle.asn1.cms.TimeStampedData;
	using CMSException = org.bouncycastle.cms.CMSException;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;

	public class CMSTimeStampedData
	{
		private TimeStampedData timeStampedData;
		private ContentInfo contentInfo;
		private TimeStampDataUtil util;

		public CMSTimeStampedData(ContentInfo contentInfo)
		{
			this.initialize(contentInfo);
		}

		public CMSTimeStampedData(InputStream @in)
		{
			try
			{
				initialize(ContentInfo.getInstance((new ASN1InputStream(@in)).readObject()));
			}
			catch (ClassCastException e)
			{
				throw new IOException("Malformed content: " + e);
			}
			catch (IllegalArgumentException e)
			{
				throw new IOException("Malformed content: " + e);
			}
		}

		public CMSTimeStampedData(byte[] baseData) : this(new ByteArrayInputStream(baseData))
		{
		}

		private void initialize(ContentInfo contentInfo)
		{
			this.contentInfo = contentInfo;

			if (CMSObjectIdentifiers_Fields.timestampedData.Equals(contentInfo.getContentType()))
			{
				this.timeStampedData = TimeStampedData.getInstance(contentInfo.getContent());
			}
			else
			{
				throw new IllegalArgumentException("Malformed content - type must be " + CMSObjectIdentifiers_Fields.timestampedData.getId());
			}

			util = new TimeStampDataUtil(this.timeStampedData);
		}

		public virtual byte[] calculateNextHash(DigestCalculator calculator)
		{
			return util.calculateNextHash(calculator);
		}

		/// <summary>
		/// Return a new timeStampedData object with the additional token attached.
		/// </summary>
		/// <exception cref="CMSException"> </exception>
		public virtual CMSTimeStampedData addTimeStamp(TimeStampToken token)
		{
			TimeStampAndCRL[] timeStamps = util.getTimeStamps();
			TimeStampAndCRL[] newTimeStamps = new TimeStampAndCRL[timeStamps.Length + 1];

			JavaSystem.arraycopy(timeStamps, 0, newTimeStamps, 0, timeStamps.Length);

			newTimeStamps[timeStamps.Length] = new TimeStampAndCRL(token.toCMSSignedData().toASN1Structure());

			return new CMSTimeStampedData(new ContentInfo(CMSObjectIdentifiers_Fields.timestampedData, new TimeStampedData(timeStampedData.getDataUri(), timeStampedData.getMetaData(), timeStampedData.getContent(), new Evidence(new TimeStampTokenEvidence(newTimeStamps)))));
		}

		public virtual byte[] getContent()
		{
			if (timeStampedData.getContent() != null)
			{
				return timeStampedData.getContent().getOctets();
			}

			return null;
		}

		public virtual URI getDataUri()
		{
			DERIA5String dataURI = this.timeStampedData.getDataUri();

			if (dataURI != null)
			{
				return new URI(dataURI.getString());
			}

			return null;
		}

		public virtual string getFileName()
		{
			return util.getFileName();
		}

		public virtual string getMediaType()
		{
			return util.getMediaType();
		}

		public virtual AttributeTable getOtherMetaData()
		{
			return util.getOtherMetaData();
		}

		public virtual TimeStampToken[] getTimeStampTokens()
		{
			return util.getTimeStampTokens();
		}

		/// <summary>
		/// Initialise the passed in calculator with the MetaData for this message, if it is
		/// required as part of the initial message imprint calculation.
		/// </summary>
		/// <param name="calculator"> the digest calculator to be initialised. </param>
		/// <exception cref="CMSException"> if the MetaData is required and cannot be processed </exception>
		public virtual void initialiseMessageImprintDigestCalculator(DigestCalculator calculator)
		{
			util.initialiseMessageImprintDigestCalculator(calculator);
		}

		/// <summary>
		/// Returns an appropriately initialised digest calculator based on the message imprint algorithm
		/// described in the first time stamp in the TemporalData for this message. If the metadata is required
		/// to be included in the digest calculation, the returned calculator will be pre-initialised.
		/// </summary>
		/// <param name="calculatorProvider">  a provider of DigestCalculator objects. </param>
		/// <returns> an initialised digest calculator. </returns>
		/// <exception cref="OperatorCreationException"> if the provider is unable to create the calculator. </exception>
		public virtual DigestCalculator getMessageImprintDigestCalculator(DigestCalculatorProvider calculatorProvider)
		{
			return util.getMessageImprintDigestCalculator(calculatorProvider);
		}

		/// <summary>
		/// Validate the digests present in the TimeStampTokens contained in the CMSTimeStampedData.
		/// </summary>
		/// <param name="calculatorProvider"> provider for digest calculators </param>
		/// <param name="dataDigest"> the calculated data digest for the message </param>
		/// <exception cref="ImprintDigestInvalidException"> if an imprint digest fails to compare </exception>
		/// <exception cref="CMSException">  if an exception occurs processing the message. </exception>
		public virtual void validate(DigestCalculatorProvider calculatorProvider, byte[] dataDigest)
		{
			util.validate(calculatorProvider, dataDigest);
		}

		/// <summary>
		/// Validate the passed in timestamp token against the tokens and data present in the message.
		/// </summary>
		/// <param name="calculatorProvider"> provider for digest calculators </param>
		/// <param name="dataDigest"> the calculated data digest for the message. </param>
		/// <param name="timeStampToken">  the timestamp token of interest. </param>
		/// <exception cref="ImprintDigestInvalidException"> if the token is not present in the message, or an imprint digest fails to compare. </exception>
		/// <exception cref="CMSException"> if an exception occurs processing the message. </exception>
		public virtual void validate(DigestCalculatorProvider calculatorProvider, byte[] dataDigest, TimeStampToken timeStampToken)
		{
			util.validate(calculatorProvider, dataDigest, timeStampToken);
		}

		public virtual byte[] getEncoded()
		{
			return contentInfo.getEncoded();
		}
	}

}