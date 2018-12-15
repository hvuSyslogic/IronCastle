
using BouncyCastle.Core.Port.java.text;

namespace org.bouncycastle.asn1.dvcs
{

	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;

	/// <summary>
	/// <pre>
	///     DVCSTime ::= CHOICE  {
	///         genTime                      GeneralizedTime,
	///         timeStampToken               ContentInfo
	///     }
	/// </pre>
	/// </summary>
	public class DVCSTime : ASN1Object, ASN1Choice
	{
		private readonly ASN1GeneralizedTime genTime;
		private readonly ContentInfo timeStampToken;

		// constructors:

		public DVCSTime(DateTime time) : this(new ASN1GeneralizedTime(time))
		{
		}

		public DVCSTime(ASN1GeneralizedTime genTime)
		{
			this.genTime = genTime;
			this.timeStampToken = null;
		}

		public DVCSTime(ContentInfo timeStampToken)
		{
			this.genTime = null;
			this.timeStampToken = timeStampToken;
		}

		public static DVCSTime getInstance(object obj)
		{
			if (obj is DVCSTime)
			{
				return (DVCSTime)obj;
			}
			else if (obj is ASN1GeneralizedTime)
			{
				return new DVCSTime(ASN1GeneralizedTime.getInstance(obj));
			}
			else if (obj != null)
			{
				return new DVCSTime(ContentInfo.getInstance(obj));
			}

			return null;
		}

		public static DVCSTime getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(obj.getObject()); // must be explicitly tagged
		}


		// selectors:

		public virtual ASN1GeneralizedTime getGenTime()
		{
			return genTime;
		}

		public virtual ContentInfo getTimeStampToken()
		{
			return timeStampToken;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			if (genTime != null)
			{
				return genTime;
			}
			else
			{
				return timeStampToken.toASN1Primitive();
			}
		}

		public override string ToString()
		{
			if (genTime != null)
			{
				return genTime.ToString();
			}
			else
			{
				return timeStampToken.ToString();
			}
		}
	}

}