using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	public class Attribute : ASN1Object
	{
		private ASN1ObjectIdentifier attrType;
		private ASN1Set attrValues;

		/// <summary>
		/// return an Attribute object from the given object.
		/// </summary>
		/// <param name="o"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static Attribute getInstance(object o)
		{
			if (o is Attribute)
			{
				return (Attribute)o;
			}

			if (o != null)
			{
				return new Attribute(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		private Attribute(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			attrType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
			attrValues = ASN1Set.getInstance(seq.getObjectAt(1));
		}

		public Attribute(ASN1ObjectIdentifier attrType, ASN1Set attrValues)
		{
			this.attrType = attrType;
			this.attrValues = attrValues;
		}

		public virtual ASN1ObjectIdentifier getAttrType()
		{
			return new ASN1ObjectIdentifier(attrType.getId());
		}

		public virtual ASN1Encodable[] getAttributeValues()
		{
			return attrValues.toArray();
		}

		public virtual ASN1Set getAttrValues()
		{
			return attrValues;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// Attribute ::= SEQUENCE {
		///     attrType OBJECT IDENTIFIER,
		///     attrValues SET OF AttributeValue
		/// }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(attrType);
			v.add(attrValues);

			return new DERSequence(v);
		}
	}

}