using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x500
{

	/// <summary>
	/// Holding class for the AttributeTypeAndValue structures that make up an RDN.
	/// </summary>
	public class AttributeTypeAndValue : ASN1Object
	{
		private ASN1ObjectIdentifier type;
		private ASN1Encodable value;

		private AttributeTypeAndValue(ASN1Sequence seq)
		{
			type = (ASN1ObjectIdentifier)seq.getObjectAt(0);
			value = seq.getObjectAt(1);
		}

		public static AttributeTypeAndValue getInstance(object o)
		{
			if (o is AttributeTypeAndValue)
			{
				return (AttributeTypeAndValue)o;
			}
			else if (o != null)
			{
				return new AttributeTypeAndValue(ASN1Sequence.getInstance(o));
			}

			throw new IllegalArgumentException("null value in getInstance()");
		}

		public AttributeTypeAndValue(ASN1ObjectIdentifier type, ASN1Encodable value)
		{
			this.type = type;
			this.value = value;
		}

		public virtual ASN1ObjectIdentifier getType()
		{
			return type;
		}

		public virtual ASN1Encodable getValue()
		{
			return value;
		}

		/// <summary>
		/// <pre>
		/// AttributeTypeAndValue ::= SEQUENCE {
		///           type         OBJECT IDENTIFIER,
		///           value        ANY DEFINED BY type }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(type);
			v.add(value);

			return new DERSequence(v);
		}
	}

}