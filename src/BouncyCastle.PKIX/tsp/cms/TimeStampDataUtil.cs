using org.bouncycastle.asn1;

namespace org.bouncycastle.tsp.cms
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using Evidence = org.bouncycastle.asn1.cms.Evidence;
	using TimeStampAndCRL = org.bouncycastle.asn1.cms.TimeStampAndCRL;
	using TimeStampedData = org.bouncycastle.asn1.cms.TimeStampedData;
	using TimeStampedDataParser = org.bouncycastle.asn1.cms.TimeStampedDataParser;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CMSException = org.bouncycastle.cms.CMSException;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using Arrays = org.bouncycastle.util.Arrays;

	public class TimeStampDataUtil
	{
		private readonly TimeStampAndCRL[] timeStamps;

		private readonly MetaDataUtil metaDataUtil;

		public TimeStampDataUtil(TimeStampedData timeStampedData)
		{
			this.metaDataUtil = new MetaDataUtil(timeStampedData.getMetaData());

			Evidence evidence = timeStampedData.getTemporalEvidence();
			this.timeStamps = evidence.getTstEvidence().toTimeStampAndCRLArray();
		}

		public TimeStampDataUtil(TimeStampedDataParser timeStampedData)
		{
			this.metaDataUtil = new MetaDataUtil(timeStampedData.getMetaData());

			Evidence evidence = timeStampedData.getTemporalEvidence();
			this.timeStamps = evidence.getTstEvidence().toTimeStampAndCRLArray();
		}

		public virtual TimeStampToken getTimeStampToken(TimeStampAndCRL timeStampAndCRL)
		{
			ContentInfo timeStampToken = timeStampAndCRL.getTimeStampToken();

			try
			{
				TimeStampToken token = new TimeStampToken(timeStampToken);
				return token;
			}
			catch (IOException e)
			{
				throw new CMSException("unable to parse token data: " + e.Message, e);
			}
			catch (TSPException e)
			{
				if (e.InnerException is CMSException)
				{
					throw (CMSException)e.InnerException;
				}

				throw new CMSException("token data invalid: " + e.Message, e);
			}
			catch (IllegalArgumentException e)
			{
				throw new CMSException("token data invalid: " + e.Message, e);
			}
		}

		public virtual void initialiseMessageImprintDigestCalculator(DigestCalculator calculator)
		{
			metaDataUtil.initialiseMessageImprintDigestCalculator(calculator);
		}

		public virtual DigestCalculator getMessageImprintDigestCalculator(DigestCalculatorProvider calculatorProvider)
		{
			TimeStampToken token;

			try
			{
				token = this.getTimeStampToken(timeStamps[0]);

				TimeStampTokenInfo info = token.getTimeStampInfo();
				ASN1ObjectIdentifier algOID = info.getMessageImprintAlgOID();

				DigestCalculator calc = calculatorProvider.get(new AlgorithmIdentifier(algOID));

				initialiseMessageImprintDigestCalculator(calc);

				return calc;
			}
			catch (CMSException e)
			{
				throw new OperatorCreationException("unable to extract algorithm ID: " + e.Message, e);
			}
		}

		public virtual TimeStampToken[] getTimeStampTokens()
		{
			TimeStampToken[] tokens = new TimeStampToken[timeStamps.Length];
			for (int i = 0; i < timeStamps.Length; i++)
			{
				tokens[i] = this.getTimeStampToken(timeStamps[i]);
			}

			return tokens;
		}

		public virtual TimeStampAndCRL[] getTimeStamps()
		{
			return timeStamps;
		}

		public virtual byte[] calculateNextHash(DigestCalculator calculator)
		{
			TimeStampAndCRL tspToken = timeStamps[timeStamps.Length - 1];

			OutputStream @out = calculator.getOutputStream();

			try
			{
				@out.write(tspToken.getEncoded(ASN1Encoding_Fields.DER));

				@out.close();

				return calculator.getDigest();
			}
			catch (IOException e)
			{
				throw new CMSException("exception calculating hash: " + e.Message, e);
			}
		}

		/// <summary>
		/// Validate the digests present in the TimeStampTokens contained in the CMSTimeStampedData.
		/// </summary>
		public virtual void validate(DigestCalculatorProvider calculatorProvider, byte[] dataDigest)
		{
			byte[] currentDigest = dataDigest;

			for (int i = 0; i < timeStamps.Length; i++)
			{
				try
				{
					TimeStampToken token = this.getTimeStampToken(timeStamps[i]);
					if (i > 0)
					{
						TimeStampTokenInfo info = token.getTimeStampInfo();
						DigestCalculator calculator = calculatorProvider.get(info.getHashAlgorithm());

						calculator.getOutputStream().write(timeStamps[i - 1].getEncoded(ASN1Encoding_Fields.DER));

						currentDigest = calculator.getDigest();
					}

					this.compareDigest(token, currentDigest);
				}
				catch (IOException e)
				{
					throw new CMSException("exception calculating hash: " + e.Message, e);
				}
				catch (OperatorCreationException e)
				{
					throw new CMSException("cannot create digest: " + e.Message, e);
				}
			}
		}

		public virtual void validate(DigestCalculatorProvider calculatorProvider, byte[] dataDigest, TimeStampToken timeStampToken)
		{
			byte[] currentDigest = dataDigest;
			byte[] encToken;

			try
			{
				encToken = timeStampToken.getEncoded();
			}
			catch (IOException e)
			{
				throw new CMSException("exception encoding timeStampToken: " + e.Message, e);
			}

			for (int i = 0; i < timeStamps.Length; i++)
			{
				try
				{
					TimeStampToken token = this.getTimeStampToken(timeStamps[i]);
					if (i > 0)
					{
						TimeStampTokenInfo info = token.getTimeStampInfo();
						DigestCalculator calculator = calculatorProvider.get(info.getHashAlgorithm());

						calculator.getOutputStream().write(timeStamps[i - 1].getEncoded(ASN1Encoding_Fields.DER));

						currentDigest = calculator.getDigest();
					}

					this.compareDigest(token, currentDigest);

					if (Arrays.areEqual(token.getEncoded(), encToken))
					{
						return;
					}
				}
				catch (IOException e)
				{
					throw new CMSException("exception calculating hash: " + e.Message, e);
				}
				catch (OperatorCreationException e)
				{
					throw new CMSException("cannot create digest: " + e.Message, e);
				}
			}

			throw new ImprintDigestInvalidException("passed in token not associated with timestamps present", timeStampToken);
		}

		private void compareDigest(TimeStampToken timeStampToken, byte[] digest)
		{
			TimeStampTokenInfo info = timeStampToken.getTimeStampInfo();
			byte[] tsrMessageDigest = info.getMessageImprintDigest();

			if (!Arrays.areEqual(digest, tsrMessageDigest))
			{
				throw new ImprintDigestInvalidException("hash calculated is different from MessageImprintDigest found in TimeStampToken", timeStampToken);
			}
		}

		public virtual string getFileName()
		{
			return metaDataUtil.getFileName();
		}

		public virtual string getMediaType()
		{
			return metaDataUtil.getMediaType();
		}

		public virtual AttributeTable getOtherMetaData()
		{
			return new AttributeTable(metaDataUtil.getOtherMetaData());
		}
	}

}