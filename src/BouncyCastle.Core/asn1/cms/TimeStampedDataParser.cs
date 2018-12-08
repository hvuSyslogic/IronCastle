namespace org.bouncycastle.asn1.cms
{


	/// <summary>
	/// Parser for <a href="http://tools.ietf.org/html/rfc5544">RFC 5544</a>:
	/// <seealso cref="TimeStampedData"/> object.
	/// <para>
	/// <pre>
	/// TimeStampedData ::= SEQUENCE {
	///   version              INTEGER { v1(1) },
	///   dataUri              IA5String OPTIONAL,
	///   metaData             MetaData OPTIONAL,
	///   content              OCTET STRING OPTIONAL,
	///   temporalEvidence     Evidence
	/// }
	/// </pre>
	/// </para>
	/// </summary>
	public class TimeStampedDataParser
	{
		private ASN1Integer version;
		private DERIA5String dataUri;
		private MetaData metaData;
		private ASN1OctetStringParser content;
		private Evidence temporalEvidence;
		private ASN1SequenceParser parser;

		private TimeStampedDataParser(ASN1SequenceParser parser)
		{
			this.parser = parser;
			this.version = ASN1Integer.getInstance(parser.readObject());

			ASN1Encodable obj = parser.readObject();

			if (obj is DERIA5String)
			{
				this.dataUri = DERIA5String.getInstance(obj);
				obj = parser.readObject();
			}
			if (obj is MetaData || obj is ASN1SequenceParser)
			{
				this.metaData = MetaData.getInstance(obj.toASN1Primitive());
				obj = parser.readObject();
			}
			if (obj is ASN1OctetStringParser)
			{
				this.content = (ASN1OctetStringParser)obj;
			}
		}

		public static TimeStampedDataParser getInstance(object obj)
		{
			if (obj is ASN1Sequence)
			{
				return new TimeStampedDataParser(((ASN1Sequence)obj).parser());
			}
			if (obj is ASN1SequenceParser)
			{
				return new TimeStampedDataParser((ASN1SequenceParser)obj);
			}

			return null;
		}

		public virtual DERIA5String getDataUri()
		{
			return dataUri;
		}

		public virtual MetaData getMetaData()
		{
			return metaData;
		}

		public virtual ASN1OctetStringParser getContent()
		{
			return content;
		}

		public virtual Evidence getTemporalEvidence()
		{
			if (temporalEvidence == null)
			{
				temporalEvidence = Evidence.getInstance(parser.readObject().toASN1Primitive());
			}

			return temporalEvidence;
		}
	}

}