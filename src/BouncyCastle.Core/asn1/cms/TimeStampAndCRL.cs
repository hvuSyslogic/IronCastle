using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{
	
	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5544">RFC 5544</a>
	/// Binding Documents with Time-Stamps; TimeStampAndCRL object.
	/// <pre>
	/// TimeStampAndCRL ::= SEQUENCE {
	///     timeStamp   TimeStampToken,          -- according to RFC 3161
	///     crl         CertificateList OPTIONAL -- according to RFC 5280
	///  }
	/// </pre>
	/// </summary>
	public class TimeStampAndCRL : ASN1Object
	{
		private ContentInfo timeStamp;
		private CertificateList crl;

		public TimeStampAndCRL(ContentInfo timeStamp)
		{
			this.timeStamp = timeStamp;
		}

		private TimeStampAndCRL(ASN1Sequence seq)
		{
			this.timeStamp = ContentInfo.getInstance(seq.getObjectAt(0));
			if (seq.size() == 2)
			{
				this.crl = CertificateList.getInstance(seq.getObjectAt(1));
			}
		}

		/// <summary>
		/// Return a TimeStampAndCRL object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="TimeStampAndCRL"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with TimeStampAndCRL structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static TimeStampAndCRL getInstance(object obj)
		{
			if (obj is TimeStampAndCRL)
			{
				return (TimeStampAndCRL)obj;
			}
			else if (obj != null)
			{
				return new TimeStampAndCRL(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ContentInfo getTimeStampToken()
		{
			return this.timeStamp;
		}

		/// @deprecated use getCRL() 
		public virtual CertificateList getCertificateList()
		{
			return this.crl;
		}

		public virtual CertificateList getCRL()
		{
			return this.crl;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(timeStamp);

			if (crl != null)
			{
				v.add(crl);
			}

			return new DERSequence(v);
		}
	}

}