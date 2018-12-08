using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{

	/// <summary>
	/// TaggedAttribute from RFC5272
	/// <pre>
	/// TaggedAttribute ::= SEQUENCE {
	/// bodyPartID         BodyPartID,
	/// attrType           OBJECT IDENTIFIER,
	/// attrValues         SET OF AttributeValue
	/// }
	/// </pre>
	/// </summary>
	public class TaggedAttribute : ASN1Object
	{
		private readonly BodyPartID bodyPartID;
		private readonly ASN1ObjectIdentifier attrType;
		private readonly ASN1Set attrValues;

		public static TaggedAttribute getInstance(object o)
		{
			if (o is TaggedAttribute)
			{
				return (TaggedAttribute)o;
			}

			if (o != null)
			{
				return new TaggedAttribute(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		private TaggedAttribute(ASN1Sequence seq)
		{
			if (seq.size() != 3)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.bodyPartID = BodyPartID.getInstance(seq.getObjectAt(0));
			this.attrType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
			this.attrValues = ASN1Set.getInstance(seq.getObjectAt(2));
		}

		public TaggedAttribute(BodyPartID bodyPartID, ASN1ObjectIdentifier attrType, ASN1Set attrValues)
		{
			this.bodyPartID = bodyPartID;
			this.attrType = attrType;
			this.attrValues = attrValues;
		}

		public virtual BodyPartID getBodyPartID()
		{
			return bodyPartID;
		}

		public virtual ASN1ObjectIdentifier getAttrType()
		{
			return attrType;
		}

		public virtual ASN1Set getAttrValues()
		{
			return attrValues;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new DERSequence(new ASN1Encodable[]{bodyPartID, attrType, attrValues});
		}
	}


}