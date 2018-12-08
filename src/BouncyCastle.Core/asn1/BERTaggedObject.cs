using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// BER TaggedObject - in ASN.1 notation this is any object preceded by
	/// a [n] where n is some number - these are assumed to follow the construction
	/// rules (as with sequences).
	/// </summary>
	public class BERTaggedObject : ASN1TaggedObject
	{
		/// <param name="tagNo"> the tag number for this object. </param>
		/// <param name="obj"> the tagged object. </param>
		public BERTaggedObject(int tagNo, ASN1Encodable obj) : base(true, tagNo, obj)
		{
		}

		/// <param name="explicit"> true if an explicitly tagged object. </param>
		/// <param name="tagNo"> the tag number for this object. </param>
		/// <param name="obj"> the tagged object. </param>
		public BERTaggedObject(bool @explicit, int tagNo, ASN1Encodable obj) : base(@explicit, tagNo, obj)
		{
		}

		/// <summary>
		/// create an implicitly tagged object that contains a zero
		/// length sequence.
		/// </summary>
		public BERTaggedObject(int tagNo) : base(false, tagNo, new BERSequence())
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
					ASN1Primitive primitive = obj.toASN1Primitive().toDERObject();

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
				ASN1Primitive primitive = obj.toASN1Primitive();
				int length = primitive.encodedLength();

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
			@out.writeTag(BERTags_Fields.CONSTRUCTED | BERTags_Fields.TAGGED, tagNo);
			@out.write(0x80);

			if (!empty)
			{
				if (!@explicit)
				{
					Enumeration e;
					if (obj is ASN1OctetString)
					{
						if (obj is BEROctetString)
						{
							e = ((BEROctetString)obj).getObjects();
						}
						else
						{
							ASN1OctetString octs = (ASN1OctetString)obj;
							BEROctetString berO = new BEROctetString(octs.getOctets());
							e = berO.getObjects();
						}
					}
					else if (obj is ASN1Sequence)
					{
						e = ((ASN1Sequence)obj).getObjects();
					}
					else if (obj is ASN1Set)
					{
						e = ((ASN1Set)obj).getObjects();
					}
					else
					{
						throw new ASN1Exception("not implemented: " + obj.GetType().getName());
					}

					while (e.hasMoreElements())
					{
						@out.writeObject((ASN1Encodable)e.nextElement());
					}
				}
				else
				{
					@out.writeObject(obj);
				}
			}

			@out.write(0x00);
			@out.write(0x00);
		}
	}

}