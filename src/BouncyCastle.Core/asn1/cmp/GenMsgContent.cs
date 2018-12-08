namespace org.bouncycastle.asn1.cmp
{

	public class GenMsgContent : ASN1Object
	{
		private ASN1Sequence content;

		private GenMsgContent(ASN1Sequence seq)
		{
			content = seq;
		}

		public static GenMsgContent getInstance(object o)
		{
			if (o is GenMsgContent)
			{
				return (GenMsgContent)o;
			}

			if (o != null)
			{
				return new GenMsgContent(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public GenMsgContent(InfoTypeAndValue itv)
		{
			content = new DERSequence(itv);
		}

		public GenMsgContent(InfoTypeAndValue[] itv)
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
		/// GenMsgContent ::= SEQUENCE OF InfoTypeAndValue
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return content;
		}
	}

}