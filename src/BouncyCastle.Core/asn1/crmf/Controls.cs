namespace org.bouncycastle.asn1.crmf
{

	public class Controls : ASN1Object
	{
		private ASN1Sequence content;

		private Controls(ASN1Sequence seq)
		{
			content = seq;
		}

		public static Controls getInstance(object o)
		{
			if (o is Controls)
			{
				return (Controls)o;
			}

			if (o != null)
			{
				return new Controls(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public Controls(AttributeTypeAndValue atv)
		{
			content = new DERSequence(atv);
		}

		public Controls(AttributeTypeAndValue[] atvs)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			for (int i = 0; i < atvs.Length; i++)
			{
				v.add(atvs[i]);
			}
			content = new DERSequence(v);
		}

		public virtual AttributeTypeAndValue[] toAttributeTypeAndValueArray()
		{
			AttributeTypeAndValue[] result = new AttributeTypeAndValue[content.size()];

			for (int i = 0; i != result.Length; i++)
			{
				result[i] = AttributeTypeAndValue.getInstance(content.getObjectAt(i));
			}

			return result;
		}

		/// <summary>
		/// <pre>
		/// Controls  ::= SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue
		/// </pre>
		/// </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return content;
		}
	}

}