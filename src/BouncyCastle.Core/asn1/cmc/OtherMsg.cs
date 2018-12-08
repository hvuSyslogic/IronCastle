using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{

	/// <summary>
	/// <pre>
	/// OtherMsg ::= SEQUENCE {
	///     bodyPartID        BodyPartID,
	///     otherMsgType      OBJECT IDENTIFIER,
	///     otherMsgValue     ANY DEFINED BY otherMsgType }
	/// </pre>
	/// </summary>
	public class OtherMsg : ASN1Object
	{
		private readonly BodyPartID bodyPartID;
		private readonly ASN1ObjectIdentifier otherMsgType;
		private readonly ASN1Encodable otherMsgValue;

		public OtherMsg(BodyPartID bodyPartID, ASN1ObjectIdentifier otherMsgType, ASN1Encodable otherMsgValue)
		{
			this.bodyPartID = bodyPartID;
			this.otherMsgType = otherMsgType;
			this.otherMsgValue = otherMsgValue;
		}

		private OtherMsg(ASN1Sequence seq)
		{
			if (seq.size() != 3)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.bodyPartID = BodyPartID.getInstance(seq.getObjectAt(0));
			this.otherMsgType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
			this.otherMsgValue = seq.getObjectAt(2);
		}

		public static OtherMsg getInstance(object o)
		{
			if (o is OtherMsg)
			{
				return (OtherMsg)o;
			}

			if (o != null)
			{
				return new OtherMsg(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public static OtherMsg getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(bodyPartID);
			v.add(otherMsgType);
			v.add(otherMsgValue);

			return new DERSequence(v);
		}

		public virtual BodyPartID getBodyPartID()
		{
			return bodyPartID;
		}

		public virtual ASN1ObjectIdentifier getOtherMsgType()
		{
			return otherMsgType;
		}

		public virtual ASN1Encodable getOtherMsgValue()
		{
			return otherMsgValue;
		}
	}

}