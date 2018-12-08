namespace org.bouncycastle.asn1.cmp
{

	public class POPODecKeyRespContent : ASN1Object
	{
		private ASN1Sequence content;

		private POPODecKeyRespContent(ASN1Sequence seq)
		{
			content = seq;
		}

		public static POPODecKeyRespContent getInstance(object o)
		{
			if (o is POPODecKeyRespContent)
			{
				return (POPODecKeyRespContent)o;
			}

			if (o != null)
			{
				return new POPODecKeyRespContent(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual ASN1Integer[] toASN1IntegerArray()
		{
			ASN1Integer[] result = new ASN1Integer[content.size()];

			for (int i = 0; i != result.Length; i++)
			{
				result[i] = ASN1Integer.getInstance(content.getObjectAt(i));
			}

			return result;
		}

		/// <summary>
		/// <pre>
		/// POPODecKeyRespContent ::= SEQUENCE OF INTEGER
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return content;
		}
	}

}