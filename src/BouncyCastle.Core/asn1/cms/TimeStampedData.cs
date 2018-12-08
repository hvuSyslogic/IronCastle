using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5544">RFC 5544</a>:
	/// Binding Documents with Time-Stamps; TimeStampedData object.
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
	public class TimeStampedData : ASN1Object
	{
		private ASN1Integer version;
		private DERIA5String dataUri;
		private MetaData metaData;
		private ASN1OctetString content;
		private Evidence temporalEvidence;

		public TimeStampedData(DERIA5String dataUri, MetaData metaData, ASN1OctetString content, Evidence temporalEvidence)
		{
			this.version = new ASN1Integer(1);
			this.dataUri = dataUri;
			this.metaData = metaData;
			this.content = content;
			this.temporalEvidence = temporalEvidence;
		}

		private TimeStampedData(ASN1Sequence seq)
		{
			this.version = ASN1Integer.getInstance(seq.getObjectAt(0));

			int index = 1;
			if (seq.getObjectAt(index) is DERIA5String)
			{
				this.dataUri = DERIA5String.getInstance(seq.getObjectAt(index++));
			}
			if (seq.getObjectAt(index) is MetaData || seq.getObjectAt(index) is ASN1Sequence)
			{
				this.metaData = MetaData.getInstance(seq.getObjectAt(index++));
			}
			if (seq.getObjectAt(index) is ASN1OctetString)
			{
				this.content = ASN1OctetString.getInstance(seq.getObjectAt(index++));
			}
			this.temporalEvidence = Evidence.getInstance(seq.getObjectAt(index));
		}

		/// <summary>
		/// Return a TimeStampedData object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="RecipientKeyIdentifier"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with TimeStampedData structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static TimeStampedData getInstance(object obj)
		{
			if (obj == null || obj is TimeStampedData)
			{
				return (TimeStampedData)obj;
			}
			return new TimeStampedData(ASN1Sequence.getInstance(obj));
		}

		public virtual DERIA5String getDataUri()
		{
			return dataUri;
		}

		public virtual MetaData getMetaData()
		{
			return metaData;
		}

		public virtual ASN1OctetString getContent()
		{
			return content;
		}

		public virtual Evidence getTemporalEvidence()
		{
			return temporalEvidence;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(version);

			if (dataUri != null)
			{
				v.add(dataUri);
			}

			if (metaData != null)
			{
				v.add(metaData);
			}

			if (content != null)
			{
				v.add(content);
			}

			v.add(temporalEvidence);

			return new BERSequence(v);
		}
	}

}