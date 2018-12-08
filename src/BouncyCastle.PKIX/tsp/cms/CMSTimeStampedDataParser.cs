using org.bouncycastle.asn1.cms;
using org.bouncycastle.asn1;

namespace org.bouncycastle.tsp.cms
{

	using BERTags = org.bouncycastle.asn1.BERTags;
	using DERIA5String = org.bouncycastle.asn1.DERIA5String;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using ContentInfoParser = org.bouncycastle.asn1.cms.ContentInfoParser;
	using TimeStampedDataParser = org.bouncycastle.asn1.cms.TimeStampedDataParser;
	using CMSContentInfoParser = org.bouncycastle.cms.CMSContentInfoParser;
	using CMSException = org.bouncycastle.cms.CMSException;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using Streams = org.bouncycastle.util.io.Streams;

	public class CMSTimeStampedDataParser : CMSContentInfoParser
	{
		private TimeStampedDataParser timeStampedData;
		private TimeStampDataUtil util;

		public CMSTimeStampedDataParser(InputStream @in) : base(@in)
		{

			initialize(_contentInfo);
		}

		public CMSTimeStampedDataParser(byte[] baseData) : this(new ByteArrayInputStream(baseData))
		{
		}

		private void initialize(ContentInfoParser contentInfo)
		{
			try
			{
				if (CMSObjectIdentifiers_Fields.timestampedData.Equals(contentInfo.getContentType()))
				{
					this.timeStampedData = TimeStampedDataParser.getInstance(contentInfo.getContent(BERTags_Fields.SEQUENCE));
				}
				else
				{
					throw new IllegalArgumentException("Malformed content - type must be " + CMSObjectIdentifiers_Fields.timestampedData.getId());
				}
			}
			catch (IOException e)
			{
				throw new CMSException("parsing exception: " + e.Message, e);
			}
		}

		public virtual byte[] calculateNextHash(DigestCalculator calculator)
		{
			return util.calculateNextHash(calculator);
		}

		public virtual InputStream getContent()
		{
			if (timeStampedData.getContent() != null)
			{
				return timeStampedData.getContent().getOctetStream();
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
			try
			{
				parseTimeStamps();
			}
			catch (CMSException e)
			{
				throw new OperatorCreationException("unable to extract algorithm ID: " + e.Message, e);
			}

			return util.getMessageImprintDigestCalculator(calculatorProvider);
		}

		public virtual TimeStampToken[] getTimeStampTokens()
		{
			parseTimeStamps();

			return util.getTimeStampTokens();
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
			parseTimeStamps();

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
			parseTimeStamps();

			util.validate(calculatorProvider, dataDigest, timeStampToken);
		}

		private void parseTimeStamps()
		{
			try
			{
				if (util == null)
				{
					InputStream cont = this.getContent();

					if (cont != null)
					{
						Streams.drain(cont);
					}

					util = new TimeStampDataUtil(timeStampedData);
				}
			}
			catch (IOException e)
			{
				throw new CMSException("unable to parse evidence block: " + e.Message, e);
			}
		}
	}

}