using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.esf
{
	using ResponderID = org.bouncycastle.asn1.ocsp.ResponderID;

	/// <summary>
	/// <pre>
	/// OcspIdentifier ::= SEQUENCE {
	///     ocspResponderID ResponderID, -- As in OCSP response data
	///     producedAt GeneralizedTime -- As in OCSP response data
	/// }
	/// </pre>
	/// </summary>
	public class OcspIdentifier : ASN1Object
	{
		private ResponderID ocspResponderID;
		private ASN1GeneralizedTime producedAt;

		public static OcspIdentifier getInstance(object obj)
		{
			if (obj is OcspIdentifier)
			{
				return (OcspIdentifier)obj;
			}
			else if (obj != null)
			{
				return new OcspIdentifier(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private OcspIdentifier(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}
			this.ocspResponderID = ResponderID.getInstance(seq.getObjectAt(0));
			this.producedAt = (ASN1GeneralizedTime)seq.getObjectAt(1);
		}

		public OcspIdentifier(ResponderID ocspResponderID, ASN1GeneralizedTime producedAt)
		{
			this.ocspResponderID = ocspResponderID;
			this.producedAt = producedAt;
		}

		public virtual ResponderID getOcspResponderID()
		{
			return this.ocspResponderID;
		}

		public virtual ASN1GeneralizedTime getProducedAt()
		{
			return this.producedAt;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(this.ocspResponderID);
			v.add(this.producedAt);
			return new DERSequence(v);
		}
	}

}