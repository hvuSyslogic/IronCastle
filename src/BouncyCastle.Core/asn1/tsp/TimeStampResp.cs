using org.bouncycastle.asn1.cmp;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.tsp
{

		

	public class TimeStampResp : ASN1Object
	{
		internal PKIStatusInfo pkiStatusInfo;

		internal ContentInfo timeStampToken;

		public static TimeStampResp getInstance(object o)
		{
			if (o is TimeStampResp)
			{
				return (TimeStampResp) o;
			}
			else if (o != null)
			{
				return new TimeStampResp(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		private TimeStampResp(ASN1Sequence seq)
		{

			Enumeration e = seq.getObjects();

			// status
			pkiStatusInfo = PKIStatusInfo.getInstance(e.nextElement());

			if (e.hasMoreElements())
			{
				timeStampToken = ContentInfo.getInstance(e.nextElement());
			}
		}

		public TimeStampResp(PKIStatusInfo pkiStatusInfo, ContentInfo timeStampToken)
		{
			this.pkiStatusInfo = pkiStatusInfo;
			this.timeStampToken = timeStampToken;
		}

		public virtual PKIStatusInfo getStatus()
		{
			return pkiStatusInfo;
		}

		public virtual ContentInfo getTimeStampToken()
		{
			return timeStampToken;
		}

		/// <summary>
		/// <pre>
		/// TimeStampResp ::= SEQUENCE  {
		///   status                  PKIStatusInfo,
		///   timeStampToken          TimeStampToken     OPTIONAL  }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(pkiStatusInfo);
			if (timeStampToken != null)
			{
				v.add(timeStampToken);
			}

			return new DERSequence(v);
		}
	}

}