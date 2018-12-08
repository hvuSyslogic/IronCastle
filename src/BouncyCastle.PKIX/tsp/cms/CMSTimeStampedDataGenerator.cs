using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.tsp.cms
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using BEROctetString = org.bouncycastle.asn1.BEROctetString;
	using DERIA5String = org.bouncycastle.asn1.DERIA5String;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using Evidence = org.bouncycastle.asn1.cms.Evidence;
	using TimeStampAndCRL = org.bouncycastle.asn1.cms.TimeStampAndCRL;
	using TimeStampTokenEvidence = org.bouncycastle.asn1.cms.TimeStampTokenEvidence;
	using TimeStampedData = org.bouncycastle.asn1.cms.TimeStampedData;
	using CMSException = org.bouncycastle.cms.CMSException;
	using Streams = org.bouncycastle.util.io.Streams;

	public class CMSTimeStampedDataGenerator : CMSTimeStampedGenerator
	{
		public virtual CMSTimeStampedData generate(TimeStampToken timeStamp)
		{
			return generate(timeStamp, (InputStream)null);
		}

		public virtual CMSTimeStampedData generate(TimeStampToken timeStamp, byte[] content)
		{
			return generate(timeStamp, new ByteArrayInputStream(content));
		}

		public virtual CMSTimeStampedData generate(TimeStampToken timeStamp, InputStream content)
		{
			ByteArrayOutputStream contentOut = new ByteArrayOutputStream();

			if (content != null)
			{
				try
				{
					Streams.pipeAll(content, contentOut);
				}
				catch (IOException e)
				{
					throw new CMSException("exception encapsulating content: " + e.Message, e);
				}
			}

			ASN1OctetString encContent = null;

			if (contentOut.size() != 0)
			{
				encContent = new BEROctetString(contentOut.toByteArray());
			}

			TimeStampAndCRL stamp = new TimeStampAndCRL(timeStamp.toCMSSignedData().toASN1Structure());

			DERIA5String asn1DataUri = null;

			if (dataUri != null)
			{
				asn1DataUri = new DERIA5String(dataUri.ToString());
			}

			return new CMSTimeStampedData(new ContentInfo(CMSObjectIdentifiers_Fields.timestampedData, new TimeStampedData(asn1DataUri, metaData, encContent, new Evidence(new TimeStampTokenEvidence(stamp)))));
		}
	}


}