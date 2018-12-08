using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.cms
{


	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5544">RFC 5544</a>
	/// Binding Documents with Time-Stamps; TimeStampTokenEvidence object.
	/// <pre>
	/// TimeStampTokenEvidence ::=
	///    SEQUENCE SIZE(1..MAX) OF TimeStampAndCRL
	/// </pre>
	/// </summary>
	public class TimeStampTokenEvidence : ASN1Object
	{
		private TimeStampAndCRL[] timeStampAndCRLs;

		public TimeStampTokenEvidence(TimeStampAndCRL[] timeStampAndCRLs)
		{
			this.timeStampAndCRLs = copy(timeStampAndCRLs);
		}

		public TimeStampTokenEvidence(TimeStampAndCRL timeStampAndCRL)
		{
			this.timeStampAndCRLs = new TimeStampAndCRL[1];

			timeStampAndCRLs[0] = timeStampAndCRL;
		}

		private TimeStampTokenEvidence(ASN1Sequence seq)
		{
			this.timeStampAndCRLs = new TimeStampAndCRL[seq.size()];

			int count = 0;

			for (Enumeration en = seq.getObjects(); en.hasMoreElements();)
			{
				timeStampAndCRLs[count++] = TimeStampAndCRL.getInstance(en.nextElement());
			}
		}

		public static TimeStampTokenEvidence getInstance(ASN1TaggedObject tagged, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(tagged, @explicit));
		}

		/// <summary>
		/// Return a TimeStampTokenEvidence object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="TimeStampTokenEvidence"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with TimeStampTokenEvidence structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static TimeStampTokenEvidence getInstance(object obj)
		{
			if (obj is TimeStampTokenEvidence)
			{
				return (TimeStampTokenEvidence)obj;
			}
			else if (obj != null)
			{
				return new TimeStampTokenEvidence(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual TimeStampAndCRL[] toTimeStampAndCRLArray()
		{
			return copy(timeStampAndCRLs);
		}

		private TimeStampAndCRL[] copy(TimeStampAndCRL[] tsAndCrls)
		{
			TimeStampAndCRL[] tmp = new TimeStampAndCRL[tsAndCrls.Length];

			JavaSystem.arraycopy(tsAndCrls, 0, tmp, 0, tmp.Length);

			return tmp;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			for (int i = 0; i != timeStampAndCRLs.Length; i++)
			{
				v.add(timeStampAndCRLs[i]);
			}

			return new DERSequence(v);
		}

	}

}