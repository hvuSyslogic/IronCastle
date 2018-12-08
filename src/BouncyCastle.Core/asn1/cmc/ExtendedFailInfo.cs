using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{

	/// <summary>
	/// ExtendedFailInfo ::= SEQUENCE {
	/// failInfoOID            OBJECT IDENTIFIER,
	/// failInfoValue          ANY DEFINED BY failInfoOID
	/// }
	/// </summary>
	public class ExtendedFailInfo : ASN1Object
	{

		private readonly ASN1ObjectIdentifier failInfoOID;
		private readonly ASN1Encodable failInfoValue;

		public ExtendedFailInfo(ASN1ObjectIdentifier failInfoOID, ASN1Encodable failInfoValue)
		{
			this.failInfoOID = failInfoOID;
			this.failInfoValue = failInfoValue;
		}

		private ExtendedFailInfo(ASN1Sequence s)
		{
			if (s.size() != 2)
			{
				throw new IllegalArgumentException("Sequence must be 2 elements.");
			}

			failInfoOID = ASN1ObjectIdentifier.getInstance(s.getObjectAt(0));
			failInfoValue = s.getObjectAt(1);
		}

		public static ExtendedFailInfo getInstance(object obj)
		{
			if (obj is ExtendedFailInfo)
			{
				return (ExtendedFailInfo)obj;
			}

			if (obj is ASN1Encodable)
			{
				ASN1Encodable asn1Value = ((ASN1Encodable)obj).toASN1Primitive();
				if (asn1Value is ASN1Sequence)
				{
					return new ExtendedFailInfo((ASN1Sequence)asn1Value);
				}
			}
			else if (obj is byte[])
			{
				return getInstance(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new DERSequence(new ASN1Encodable[]{failInfoOID, failInfoValue});
		}

		public virtual ASN1ObjectIdentifier getFailInfoOID()
		{
			return failInfoOID;
		}

		public virtual ASN1Encodable getFailInfoValue()
		{
			return failInfoValue;
		}
	}

}