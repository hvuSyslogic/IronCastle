using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;

	/// <summary>
	/// <pre>
	/// TaggedContentInfo ::= SEQUENCE {
	///       bodyPartID              BodyPartID,
	///       contentInfo             ContentInfo
	/// }
	/// </pre>
	/// </summary>
	public class TaggedContentInfo : ASN1Object
	{
		private readonly BodyPartID bodyPartID;
		private readonly ContentInfo contentInfo;

		public TaggedContentInfo(BodyPartID bodyPartID, ContentInfo contentInfo)
		{
			this.bodyPartID = bodyPartID;
			this.contentInfo = contentInfo;
		}

		private TaggedContentInfo(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.bodyPartID = BodyPartID.getInstance(seq.getObjectAt(0));
			this.contentInfo = ContentInfo.getInstance(seq.getObjectAt(1));
		}

		public static TaggedContentInfo getInstance(object o)
		{
			if (o is TaggedContentInfo)
			{
				return (TaggedContentInfo)o;
			}

			if (o != null)
			{
				return new TaggedContentInfo(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public static TaggedContentInfo getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(bodyPartID);
			v.add(contentInfo);

			return new DERSequence(v);
		}

		public virtual BodyPartID getBodyPartID()
		{
			return bodyPartID;
		}

		public virtual ContentInfo getContentInfo()
		{
			return contentInfo;
		}
	}

}