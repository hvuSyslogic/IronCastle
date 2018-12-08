namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Definite Length TaggedObject - in ASN.1 notation this is any object preceded by
	/// a [n] where n is some number - these are assumed to follow the construction
	/// rules (as with sequences).
	/// </summary>
	public class DLTaggedObject : ASN1TaggedObject
	{
		private static readonly byte[] ZERO_BYTES = new byte[0];

		/// <param name="explicit"> true if an explicitly tagged object. </param>
		/// <param name="tagNo"> the tag number for this object. </param>
		/// <param name="obj"> the tagged object. </param>
		public DLTaggedObject(bool @explicit, int tagNo, ASN1Encodable obj) : base(@explicit, tagNo, obj)
		{
		}

		public override bool isConstructed()
		{
			if (!empty)
			{
				if (@explicit)
				{
					return true;
				}
				else
				{
					ASN1Primitive primitive = obj.toASN1Primitive().toDLObject();

					return primitive.isConstructed();
				}
			}
			else
			{
				return true;
			}
		}

		public override int encodedLength()
		{
			if (!empty)
			{
				int length = obj.toASN1Primitive().toDLObject().encodedLength();

				if (@explicit)
				{
					return StreamUtil.calculateTagLength(tagNo) + StreamUtil.calculateBodyLength(length) + length;
				}
				else
				{
					// header length already in calculation
					length = length - 1;

					return StreamUtil.calculateTagLength(tagNo) + length;
				}
			}
			else
			{
				return StreamUtil.calculateTagLength(tagNo) + 1;
			}
		}

		public override void encode(ASN1OutputStream @out)
		{
			if (!empty)
			{
				ASN1Primitive primitive = obj.toASN1Primitive().toDLObject();

				if (@explicit)
				{
					@out.writeTag(BERTags_Fields.CONSTRUCTED | BERTags_Fields.TAGGED, tagNo);
					@out.writeLength(primitive.encodedLength());
					@out.writeObject(primitive);
				}
				else
				{
					//
					// need to mark constructed types...
					//
					int flags;
					if (primitive.isConstructed())
					{
						flags = BERTags_Fields.CONSTRUCTED | BERTags_Fields.TAGGED;
					}
					else
					{
						flags = BERTags_Fields.TAGGED;
					}

					@out.writeTag(flags, tagNo);
					@out.writeImplicitObject(primitive);
				}
			}
			else
			{
				@out.writeEncoded(BERTags_Fields.CONSTRUCTED | BERTags_Fields.TAGGED, tagNo, ZERO_BYTES);
			}
		}
	}

}