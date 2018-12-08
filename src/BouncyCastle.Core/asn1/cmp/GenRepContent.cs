namespace org.bouncycastle.asn1.cmp
{

	public class GenRepContent : ASN1Object
	{
		private ASN1Sequence content;

		private GenRepContent(ASN1Sequence seq)
		{
			content = seq;
		}

		public static GenRepContent getInstance(object o)
		{
			if (o is GenRepContent)
			{
				return (GenRepContent)o;
			}

			if (o != null)
			{
				return new GenRepContent(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public GenRepContent(InfoTypeAndValue itv)
		{
			content = new DERSequence(itv);
		}

		public GenRepContent(InfoTypeAndValue[] itv)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			for (int i = 0; i < itv.Length; i++)
			{
				v.add(itv[i]);
			}
			content = new DERSequence(v);
		}

		public virtual InfoTypeAndValue[] toInfoTypeAndValueArray()
		{
			InfoTypeAndValue[] result = new InfoTypeAndValue[content.size()];

			for (int i = 0; i != result.Length; i++)
			{
				result[i] = InfoTypeAndValue.getInstance(content.getObjectAt(i));
			}

			return result;
		}

		/// <summary>
		/// <pre>
		/// GenRepContent ::= SEQUENCE OF InfoTypeAndValue
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return content;
		}
	}

}