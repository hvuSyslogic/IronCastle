namespace org.bouncycastle.asn1.crmf
{

	public class AttributeTypeAndValue : ASN1Object
	{
		private ASN1ObjectIdentifier type;
		private ASN1Encodable value;

		private AttributeTypeAndValue(ASN1Sequence seq)
		{
			type = (ASN1ObjectIdentifier)seq.getObjectAt(0);
			value = (ASN1Encodable)seq.getObjectAt(1);
		}

		public static AttributeTypeAndValue getInstance(object o)
		{
			if (o is AttributeTypeAndValue)
			{
				return (AttributeTypeAndValue)o;
			}

			if (o != null)
			{
				return new AttributeTypeAndValue(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public AttributeTypeAndValue(string oid, ASN1Encodable value) : this(new ASN1ObjectIdentifier(oid), value)
		{
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